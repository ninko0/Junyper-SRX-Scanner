#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
srxaudit — audit de durcissement d'une configuration Juniper SRX.

Entrée : soit la conf XML (show configuration | display xml), soit
         directement le texte "show configuration" (format curly-brace),
         ce qui est le cas le plus courant quand on n'a pas accès à
         l'export display xml. Le format est détecté automatiquement.

Sortie : une liste de remédiations classées par sévérité, chacune avec
         l'emplacement fautif, la recommandation, la référence, et — quand
         c'est sûr — la commande de correction.
         En plus du texte et du JSON, un export Excel (.xlsx) est
         disponible : un tableau des findings coloré par niveau de
         criticité (rouge=CRITICAL, orange=HIGH, jaune=MEDIUM,
         vert=LOW, gris=INFO).

Base des contrôles :
  - Durcissement Junos / CIS Juniper (services en clair, SSH, SNMP, web-mgmt…)
  - Hygiène de politiques pare-feu (NIST SP 800-41 : moindre privilège, deny+log)
  - SRX : screens (ids-option) sur zones externes, host-inbound-traffic
  - Charte interne §3.4 : protocoles obsolètes (Telnet, FTP clair, SNMP v1/2c,
    LDAP non chiffré, TLS<1.2…)

Aucune action n'est poussée : l'outil lit la conf et écrit un rapport + un
fichier de correctifs (commandes 'set'/'delete' sûres) à relire.

Aucune dépendance externe (stdlib only) — y compris pour l'export .xlsx,
généré directement en OOXML via zipfile.
"""

import argparse
import ipaddress
import json
import os
import shlex
import sys
import xml.etree.ElementTree as ET
import zipfile
from xml.sax.saxutils import escape

# --------------------------------------------------------------------------- #
# Helpers XML
# --------------------------------------------------------------------------- #

def ln(tag):
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else tag

def kids(el, name):
    return [c for c in list(el) if ln(c.tag) == name] if el is not None else []

def kid(el, name):
    for c in list(el) if el is not None else []:
        if ln(c.tag) == name:
            return c
    return None

def has(el, name):
    return kid(el, name) is not None

def txt(el, name, default=None):
    c = kid(el, name)
    if c is not None and c.text and c.text.strip():
        return c.text.strip()
    return default

def name_list(el, tag):
    """Récupère les valeurs d'une liste, que ce soit <tag><name>x</name></tag>
    ou <tag>x</tag>."""
    out = []
    for c in kids(el, tag):
        n = txt(c, "name")
        if n is None and c.text and c.text.strip():
            n = c.text.strip()
        if n:
            out.append(n)
    return out

def find_config_root(root):
    if ln(root.tag) == "configuration":
        return root
    for e in root.iter():
        if ln(e.tag) == "configuration":
            return e
    return root

def is_private(ip):
    try:
        return ipaddress.ip_address(ip.split("/")[0]).is_private
    except ValueError:
        return True

# --------------------------------------------------------------------------- #
# Parseur texte "show configuration" (curly-brace), pour quand on n'a pas
# l'export "display xml" — juste un "show configuration" copié depuis le CLI.
# --------------------------------------------------------------------------- #

def _split_tokens(s):
    try:
        toks = shlex.split(s, posix=True)
    except ValueError:
        toks = s.split()
    if "[" in toks:
        i = toks.index("[")
        try:
            j = toks.index("]", i)
        except ValueError:
            j = len(toks)
        toks = toks[:i] + toks[i + 1:j] + toks[j + 1:]
    return toks


# Les primitives de parsing texte sont importées depuis srxtool plutôt que
# dupliquées ici. C'est délibéré : quand les deux fichiers embarquaient chacun
# leur copie, un correctif appliqué d'un seul côté faisait silencieusement
# diverger l'audit et l'inventaire sur la même conf. Un seul parseur = les deux
# outils lisent forcément la configuration à l'identique.
from srxtool import (ConfigFormatError, UnsafeNameError, cbare_names,      # noqa: E402
                     cbare_value, cchild, cchildren, chas, cleaf, cleaf_all,
                     cvalues, looks_like_set_format, looks_like_xml,
                     parse_curly_text, parse_set_text, parse_text_auto, q)

# --------------------------------------------------------------------------- #
# Modèle de finding
# --------------------------------------------------------------------------- #

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

class Finding:
    __slots__ = ("sev", "check", "title", "where", "reco", "ref", "fix")
    def __init__(self, sev, check, title, where, reco, ref, fix=None):
        self.sev = sev
        self.check = check
        self.title = title
        self.where = where
        self.reco = reco
        self.ref = ref
        self.fix = fix or []   # liste de commandes set/delete, ou []

# --------------------------------------------------------------------------- #
# Parsing ciblé (services système, zones, screens, policies)
# --------------------------------------------------------------------------- #

OBSOLETE_APPS = {
    "junos-telnet": "Telnet (identifiants en clair)",
    "junos-ftp": "FTP en clair",
    "junos-tftp": "TFTP (sans authentification)",
    "junos-rlogin": "rlogin (en clair)",
    "junos-rsh": "rsh (en clair)",
    "junos-http": "HTTP en clair",
    "junos-snmp": "SNMP v1/v2c (communautés en clair)",
    "junos-snmp-agentx": "SNMP (en clair)",
    "junos-ldap": "LDAP non chiffré (389)",
    "junos-ntp": None,   # neutre, pas obsolète
}
OBSOLETE_APPS = {k: v for k, v in OBSOLETE_APPS.items() if v}

EXTERNAL_ZONE_HINT = {"untrust", "internet", "wan", "outside", "external", "inet"}
MGMT_SERVICES = {"ssh", "telnet", "http", "https", "netconf", "ssh-netconf",
                 "web-authentication", "all"}


def parse_xml(path):
    conf = find_config_root(ET.parse(path).getroot())
    m = {"system": kid(conf, "system"), "snmp": kid(conf, "snmp"),
         "security": kid(conf, "security"), "interfaces": kid(conf, "interfaces"),
         "warnings": [], "source_format": "xml"}

    units = {}
    for itf in kids(m["interfaces"], "interface"):
        iname = txt(itf, "name")
        for unit in kids(itf, "unit"):
            uname = txt(unit, "name")
            fam = kid(unit, "family")
            inet = kid(fam, "inet")
            addrs = [txt(a, "name") for a in kids(inet, "address") if txt(a, "name")]
            units[f"{iname}.{uname}"] = addrs

    sec = m["security"]

    screens = set()
    screen_root = kid(sec, "screen")
    for ids in kids(screen_root, "ids-option"):
        n = txt(ids, "name")
        if n:
            screens.add(n)

    zones = {}
    for z in kids(kid(sec, "zones"), "security-zone"):
        zn = txt(z, "name")
        ifaces = [txt(i, "name") for i in kids(z, "interfaces") if txt(i, "name")]
        hit = kid(z, "host-inbound-traffic")
        sys_services = name_list(hit, "system-services")
        protocols = name_list(hit, "protocols")
        screen = txt(z, "screen")
        public = any(any(not is_private(a) for a in units.get(i, [])) for i in ifaces)
        zones[zn] = {"interfaces": ifaces, "system_services": sys_services,
                     "protocols": protocols, "screen": screen, "public": public}

    policies = []
    for pblock in kids(kid(sec, "policies"), "policy"):
        fz = txt(pblock, "from-zone-name")
        tz = txt(pblock, "to-zone-name")
        for pol in kids(pblock, "policy"):
            match = kid(pol, "match")
            src = name_list(match, "source-address") or ["any"]
            dst = name_list(match, "destination-address") or ["any"]
            apps = name_list(match, "application") or ["any"]
            then = kid(pol, "then")
            action, logs = None, []
            if then is not None:
                for c in list(then):
                    t = ln(c.tag)
                    if t in ("permit", "deny", "reject"):
                        action = t
                    elif t == "log":
                        logs = [ln(x.tag) for x in list(c)]
            policies.append({"from_zone": fz, "to_zone": tz, "name": txt(pol, "name"),
                             "source": src, "destination": dst, "application": apps,
                             "action": action or "permit", "logs": logs})

    return m, units, screens, zones, policies


def parse_text(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    root, warnings, fmt = parse_text_auto(text)
    system = cchild(root, "system")
    snmp = cchild(root, "snmp")
    security = cchild(root, "security")
    interfaces_el = cchild(root, "interfaces")
    m = {"system": system, "snmp": snmp, "security": security,
         "interfaces": interfaces_el, "warnings": warnings, "source_format": fmt}

    # interfaces -> unité -> adresses inet
    units = {}
    for ih, inode in (interfaces_el["children"] if interfaces_el else []):
        iname = ih[0] if ih else None
        if not iname:
            continue
        for uh, unode in cchildren(inode, "unit"):
            uname = uh[0] if uh else None
            # "family inet { ... }" est UN bloc dont le header est
            # ["family", "inet"] (pas un bloc "family" imbriquant "inet").
            inet = None
            for rest, fnode in cchildren(unode, "family"):
                if rest and rest[0] == "inet":
                    inet = fnode
            addrs = cvalues(inet, "address") if inet is not None else []
            units[f"{iname}.{uname}"] = addrs

    sec = security

    screens = set()
    screen_root = cchild(sec, "screen")
    for h, ids in cchildren(screen_root, "ids-option"):
        if h:
            screens.add(h[0])

    zones = {}
    zones_root = cchild(sec, "zones")
    for h, z in cchildren(zones_root, "security-zone"):
        zn = h[0] if h else None
        if not zn:
            continue
        ifaces = cbare_names(cchild(z, "interfaces"))
        hit = cchild(z, "host-inbound-traffic")
        # cvalues() lit indifféremment 'system-services ssh;',
        # 'system-services [ ping ssh ];' et 'system-services { ping; ssh; }'.
        # L'ancienne version ne gérait que la 3e forme : une zone déclarant
        # 'system-services [ ping ssh ]' passait pour n'exposer aucun service.
        sys_services = cvalues(hit, "system-services") if hit else []
        protocols = cvalues(hit, "protocols") if hit else []
        screen = cleaf(z, "screen")
        public = any(any(not is_private(a) for a in units.get(i, [])) for i in ifaces)
        zones[zn] = {"interfaces": ifaces, "system_services": sys_services,
                     "protocols": protocols, "screen": screen, "public": public}

    policies = []
    pol_root = cchild(sec, "policies")
    for h, pblock in (pol_root["children"] if pol_root else []):
        if not (len(h) >= 4 and h[0] == "from-zone" and h[2] == "to-zone"):
            continue
        fz, tz = h[1], h[3]
        for ph, pol in cchildren(pblock, "policy"):
            pname = ph[0] if ph else None
            match = cchild(pol, "match")
            src = cvalues(match, "source-address") or ["any"]
            dst = cvalues(match, "destination-address") or ["any"]
            apps = cvalues(match, "application") or ["any"]
            then = cchild(pol, "then")
            action, logs = None, []
            if then is not None:
                for k, v in then["leaves"]:
                    if k in ("permit", "deny", "reject"):
                        action = k
                    elif k == "log":
                        logs.extend(v)
                for th, tc in then["children"]:
                    if th and th[0] in ("permit", "deny", "reject"):
                        action = th[0]
                    if th and th[0] == "log":
                        logs.extend(cbare_names(tc))
            policies.append({"from_zone": fz, "to_zone": tz, "name": pname,
                             "source": src, "destination": dst, "application": apps,
                             "action": action or "permit", "logs": logs})

    return m, units, screens, zones, policies


def parse(path, allow_empty=False):
    with open(path, encoding="utf-8", errors="replace") as fh:
        head = fh.read(500)
    if looks_like_xml(head):
        result = parse_xml(path)
    else:
        result = parse_text(path)
    m, units, screens, zones, policies = result

    # Garde-fou : ne jamais rendre un audit vide sur une conf qu'on n'a pas su
    # lire. Sans ça, une conf au format 'display set' — ou tout fichier non
    # reconnu — sortait « 0 constat » avec un code de retour 0, c'est-à-dire un
    # certificat de bonne santé délivré à un équipement jamais analysé.
    if not allow_empty and not (zones or policies or units):
        fmt = m.get("source_format", "?")
        raise ConfigFormatError(
            f"aucune donnée exploitable extraite de {os.path.basename(path)!r} "
            f"(format détecté : {fmt}). Ni zone, ni politique, ni interface n'a "
            f"été lue — le fichier n'est probablement pas une configuration SRX, "
            f"ou son format n'est pas supporté. Formats acceptés : "
            f"'show configuration' (accolades), '| display set', '| display xml'. "
            f"Utilise --allow-empty pour passer outre.")
    return result

# --------------------------------------------------------------------------- #
# Contrôles
# --------------------------------------------------------------------------- #

def check_policies(zones, policies, F):
    for p in policies:
        fz, tz, pn = p["from_zone"], p["to_zone"], p["name"]
        # q() quote les noms : sans ça, une policy nommée
        # 'BENIGN match source-address any' produisait une commande de correction
        # qui élargissait une AUTRE policy au lieu de corriger celle-ci.
        where = (f"security policies from-zone {q(fz)} to-zone {q(tz)} "
                 f"policy {q(pn)}")
        base = f"set {where}"
        is_ext = (fz in EXTERNAL_ZONE_HINT or tz in EXTERNAL_ZONE_HINT
                  or zones.get(fz, {}).get("public") or zones.get(tz, {}).get("public"))
        src_any = "any" in p["source"] or "any-ipv4" in p["source"]
        dst_any = "any" in p["destination"] or "any-ipv4" in p["destination"]
        app_any = "any" in p["application"]

        if p["action"] == "permit" and src_any and dst_any and app_any:
            F.append(Finding(
                "CRITICAL" if is_ext else "HIGH", "POL-ANY-ANY",
                "Permit total any/any/any",
                where,
                "Restreindre source, destination et application au strict "
                "nécessaire (moindre privilège). Un permit any/any/any annule "
                "l'intérêt du filtrage.",
                "NIST SP 800-41 ; charte §3.1",
                [f"# revoir puis remplacer — exemple de resserrage :",
                 f"# delete {where}",
                 f"# {base} match source-address <OBJET_SRC>",
                 f"# {base} match destination-address <OBJET_DST>",
                 f"# {base} match application <APP>"]))
        elif p["action"] == "permit" and app_any:
            F.append(Finding(
                "HIGH", "POL-APP-ANY",
                "Permit avec application any",
                where,
                "Préciser la ou les applications autorisées. 'application any' "
                "ouvre tous les ports.",
                "NIST SP 800-41 ; charte §3.1",
                [f"# delete {base.split(' match')[0]} match application any",
                 f"# {base} match application <APP_PRECISE>"]))
        elif p["action"] == "permit" and src_any and dst_any:
            F.append(Finding(
                "MEDIUM", "POL-BROAD-ADDR",
                "Permit source ET destination any",
                where,
                "Restreindre au moins l'un des deux côtés à un objet précis.",
                "Charte §3.1"))

        if p["action"] == "permit" and (fz in EXTERNAL_ZONE_HINT or
                                        zones.get(fz, {}).get("public")) and dst_any:
            F.append(Finding(
                "HIGH", "POL-INBOUND-ANY",
                "Flux entrant depuis zone externe vers destination any",
                where,
                "Un flux initié depuis Internet ne doit jamais viser 'any' en "
                "destination : cibler l'hôte publié et passer par un reverse "
                "proxy/WAF si applicable.",
                "NIST SP 800-41 ; charte §3.5"))

        for a in p["application"]:
            if a in OBSOLETE_APPS and p["action"] == "permit":
                F.append(Finding(
                    "HIGH", "POL-OBSOLETE-APP",
                    f"Protocole obsolète autorisé : {OBSOLETE_APPS[a]}",
                    where,
                    f"Remplacer {a} par l'équivalent chiffré (SSH, SFTP, HTTPS, "
                    f"LDAPS, SNMPv3) ou formaliser une dérogation datée.",
                    "Charte §3.4",
                    [f"# {base} match application {q(a)}  <-- à retirer/remplacer"]))

        if p["action"] == "permit" and not p["logs"]:
            F.append(Finding(
                "MEDIUM", "POL-NOLOG-PERMIT",
                "Permit sans journalisation",
                where,
                "Activer 'log session-close' pour la traçabilité (audit, IR).",
                "NIS2 21.2(g) ; charte §3.8",
                [f"{base} then log session-close"]))
        if p["action"] in ("deny", "reject") and "session-init" not in p["logs"]:
            F.append(Finding(
                "MEDIUM", "POL-NOLOG-DENY",
                "Deny/reject sans journalisation",
                where,
                "Activer 'log session-init' sur les deny pour détecter les "
                "tentatives d'accès refusées.",
                "NIST SP 800-41",
                [f"{base} then log session-init"]))


def check_zones(zones, screens, F):
    for zn, z in zones.items():
        where = f"security zones security-zone {q(zn)}"
        is_ext = zn in EXTERNAL_ZONE_HINT or z["public"]

        if not z["screen"] and z["interfaces"]:
            if is_ext:
                F.append(Finding(
                    "HIGH", "ZONE-NO-SCREEN",
                    "Zone externe sans screen (ids-option)",
                    where,
                    "Attacher un screen à cette zone : protection SYN-flood, "
                    "ip-spoofing, scans, land, teardrop… Baseline recommandée.",
                    "Juniper hardening (screen options)",
                    [f"# baseline de screen (à ajuster) :",
                     f"set security screen ids-option untrust-screen icmp flood threshold 1000",
                     f"set security screen ids-option untrust-screen ip spoofing",
                     f"set security screen ids-option untrust-screen tcp syn-flood alarm-threshold 1024",
                     f"set security screen ids-option untrust-screen tcp syn-flood attack-threshold 2000",
                     f"set security screen ids-option untrust-screen tcp land",
                     f"set {where} screen untrust-screen"]))
            elif z["screen"] is None:
                F.append(Finding(
                    "LOW", "ZONE-NO-SCREEN-INT",
                    "Zone interne sans screen",
                    where,
                    "Un screen même minimal (ip-spoofing) sur les zones internes "
                    "est une défense en profondeur utile.",
                    "Juniper hardening"))
        elif z["screen"] and z["screen"] not in screens:
            F.append(Finding(
                "MEDIUM", "ZONE-SCREEN-MISSING",
                f"Screen '{z['screen']}' référencé mais non défini",
                where,
                "Le screen attaché n'existe pas dans 'security screen ids-option'.",
                "Cohérence de configuration"))

        ss = set(s.lower() for s in z["system_services"])
        if "all" in ss:
            F.append(Finding(
                "CRITICAL" if is_ext else "HIGH", "ZONE-HIB-ALL",
                "host-inbound-traffic system-services = all",
                where,
                "N'autoriser que les services de gestion strictement nécessaires "
                "en entrée sur la zone (jamais 'all', surtout sur une zone "
                "externe). Exposer 'all' publie l'ensemble des services du moteur.",
                "Juniper hardening ; NIST SP 800-41",
                [f"delete {where} host-inbound-traffic system-services all",
                 f"# puis n'ajouter que le nécessaire, ex :",
                 f"# set {where} host-inbound-traffic system-services ping"]))
        else:
            if is_ext:
                exposed = ss & MGMT_SERVICES
                if exposed:
                    F.append(Finding(
                        "HIGH", "ZONE-HIB-MGMT-EXT",
                        f"Service(s) de gestion exposé(s) côté externe : "
                        f"{', '.join(sorted(exposed))}",
                        where,
                        "Ne pas exposer SSH/HTTP/HTTPS/NETCONF/Telnet en entrée "
                        "depuis une zone externe. Gérer via un réseau "
                        "d'administration dédié / VPN.",
                        "Juniper hardening",
                        [f"# delete {where} host-inbound-traffic system-services "
                         f"<{'/'.join(sorted(exposed))}>"]))
        if "all" in set(p.lower() for p in z["protocols"]):
            F.append(Finding(
                "MEDIUM", "ZONE-HIB-PROTO-ALL",
                "host-inbound-traffic protocols = all",
                where,
                "Limiter aux protocoles de routage réellement utilisés.",
                "Juniper hardening",
                [f"delete {where} host-inbound-traffic protocols all"]))


def check_system(system, snmp, F):
    services = cchild(system, "services") if isinstance(system, dict) else kid(system, "services")
    is_text = isinstance(system, dict)

    def flag_service(tag, sev, title, reco, ref):
        present = chas(services, tag) if is_text else has(services, tag)
        if present:
            F.append(Finding(sev, f"SYS-{tag.upper()}", title,
                             f"system services {tag}", reco, ref,
                             [f"delete system services {tag}"]))

    if services is not None:
        flag_service("telnet", "HIGH", "Telnet activé",
                     "Désactiver Telnet, utiliser SSH.", "CIS Juniper ; charte §3.4")
        flag_service("ftp", "MEDIUM", "Serveur FTP activé",
                     "Désactiver FTP en clair, préférer SCP/SFTP.", "CIS Juniper")
        flag_service("finger", "MEDIUM", "Service finger activé",
                     "Désactiver finger (fuite d'information).", "CIS Juniper")
        flag_service("rlogin", "HIGH", "rlogin activé",
                     "Désactiver rlogin (en clair).", "CIS Juniper")
        flag_service("rsh", "HIGH", "rsh activé",
                     "Désactiver rsh (en clair).", "CIS Juniper")
        flag_service("tftp-server", "MEDIUM", "Serveur TFTP activé",
                     "Désactiver TFTP (sans authentification).", "CIS Juniper")
        flag_service("xnm-clear-text", "HIGH", "XNM en clair (NETCONF non chiffré)",
                     "Désactiver xnm-clear-text, utiliser NETCONF sur SSH.",
                     "CIS Juniper")

        ssh = cchild(services, "ssh") if is_text else kid(services, "ssh")
        if ssh is not None:
            rl = cleaf(ssh, "root-login") if is_text else txt(ssh, "root-login")
            if rl == "allow":
                F.append(Finding("HIGH", "SYS-SSH-ROOT",
                    "SSH root-login autorisé",
                    "system services ssh root-login allow",
                    "Interdire le login root direct en SSH.",
                    "CIS Juniper",
                    ["set system services ssh root-login deny"]))
            pv = cleaf(ssh, "protocol-version") if is_text else txt(ssh, "protocol-version")
            if pv and pv.lower() == "v1":
                F.append(Finding("HIGH", "SYS-SSH-V1",
                    "SSH protocole v1 autorisé",
                    "system services ssh protocol-version v1",
                    "Forcer SSHv2 uniquement.",
                    "CIS Juniper",
                    ["set system services ssh protocol-version v2"]))

        web = cchild(services, "web-management") if is_text else kid(services, "web-management")
        web_http = (chas(web, "http") if is_text else has(web, "http")) if web is not None else False
        if web_http:
            F.append(Finding("HIGH", "SYS-WEBMGMT-HTTP",
                "Web-management en HTTP (non chiffré)",
                "system services web-management http",
                "Désactiver HTTP, n'exposer que HTTPS pour la J-Web.",
                "CIS Juniper",
                ["delete system services web-management http"]))

    syslog = cchild(system, "syslog") if is_text else kid(system, "syslog")
    if is_text:
        remote = cchildren(syslog, "host") if syslog is not None else []
    else:
        remote = kids(syslog, "host") if syslog is not None else []
    if not remote:
        F.append(Finding("MEDIUM", "SYS-NO-SYSLOG",
            "Pas de journalisation distante (syslog host)",
            "system syslog",
            "Envoyer les logs vers un collecteur/SIEM externe (traçabilité, "
            "conservation, corrélation).",
            "NIS2 21.2(g)",
            ["# set system syslog host <IP_SIEM> any info"]))

    ntp = cchild(system, "ntp") if is_text else kid(system, "ntp")
    if is_text:
        has_ntp_server = ntp is not None and (cleaf_all(ntp, "server") or cchildren(ntp, "server"))
    else:
        has_ntp_server = ntp is not None and kids(ntp, "server")
    if not has_ntp_server:
        F.append(Finding("LOW", "SYS-NO-NTP",
            "NTP non configuré",
            "system ntp",
            "Synchroniser l'horloge (indispensable pour l'horodatage des logs).",
            "CIS Juniper",
            ["# set system ntp server <IP_NTP>"]))

    login = cchild(system, "login") if is_text else kid(system, "login")
    msg = (cleaf(login, "message") if is_text else txt(login, "message")) if login is not None else None
    if login is None or not msg:
        F.append(Finding("LOW", "SYS-NO-BANNER",
            "Pas de bannière de connexion",
            "system login message",
            "Afficher un avertissement légal à la connexion.",
            "CIS Juniper",
            ['# set system login message "Acces reserve - usage autorise uniquement"']))

    if snmp is not None:
        communities = cchildren(snmp, "community") if is_text else [
            (None, c) for c in kids(snmp, "community")]
        for h, com in communities:
            cname = h[0] if (is_text and h) else (txt(com, "name") if not is_text else None)
            if is_text:
                auth = cleaf(com, "authorization", "read-only")
            else:
                cname = txt(com, "name")
                auth = txt(com, "authorization", "read-only")
            if cname and cname.lower() in ("public", "private"):
                F.append(Finding("HIGH", "SNMP-DEFAULT-COMM",
                    f"Communauté SNMP par défaut : '{cname}'",
                    f"snmp community {q(cname)}",
                    "Supprimer les communautés public/private, préférer SNMPv3.",
                    "CIS Juniper",
                    [f"delete snmp community {q(cname)}"]))
            if auth == "read-write":
                F.append(Finding("HIGH", "SNMP-RW",
                    f"Communauté SNMP en écriture : '{cname}'",
                    f"snmp community {q(cname)} authorization read-write",
                    "Éviter le read-write SNMP (surtout v1/v2c).",
                    "CIS Juniper"))
        has_v3 = (cchild(snmp, "v3") is not None) if is_text else (kid(snmp, "v3") is not None)
        if communities and not has_v3:
            F.append(Finding("MEDIUM", "SNMP-NO-V3",
                "SNMP v1/v2c utilisé, pas de v3",
                "snmp",
                "Migrer vers SNMPv3 (auth + chiffrement).",
                "CIS Juniper"))

# --------------------------------------------------------------------------- #
# Export XLSX minimaliste (stdlib only, via zipfile / OOXML)
# --------------------------------------------------------------------------- #

def _col_letter(idx):
    idx += 1
    s = ""
    while idx > 0:
        idx, r = divmod(idx - 1, 26)
        s = chr(65 + r) + s
    return s

FILLS = {
    "header":   "FF2F3B52",
    "CRITICAL": "FFC00000",
    "HIGH":     "FFFF6B6B",
    "MEDIUM":   "FFFFD966",
    "LOW":      "FFC6E0B4",
    "INFO":     "FFD9D9D9",
    "ORPHAN":   "FFFFC7CE",
    "OK":       "FFE2EFDA",
}
_FILL_ORDER = ["header", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "ORPHAN", "OK"]


def _styles_xml():
    fills = ['<fill><patternFill patternType="none"/></fill>',
             '<fill><patternFill patternType="gray125"/></fill>']
    for name in _FILL_ORDER:
        argb = FILLS[name]
        fills.append(
            f'<fill><patternFill patternType="solid">'
            f'<fgColor rgb="{argb}"/><bgColor indexed="64"/></patternFill></fill>')
    xfs = ['<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>']
    xfs.append('<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>')
    for i, name in enumerate(_FILL_ORDER[1:], start=3):
        xfs.append(f'<xf numFmtId="0" fontId="0" fillId="{i}" borderId="0" xfId="0" applyFill="1"/>')
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="2">
<font><sz val="10"/><name val="Calibri"/></font>
<font><sz val="10"/><name val="Calibri"/><b/><color rgb="FFFFFFFF"/></font>
</fonts>
<fills count="{len(fills)}">{"".join(fills)}</fills>
<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="{len(xfs)}">{"".join(xfs)}</cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>'''


def style_index(name):
    if name is None:
        return 0
    if name == "header":
        return 1
    try:
        return 2 + _FILL_ORDER[1:].index(name)
    except ValueError:
        return 0


def _sheet_xml(headers, rows, row_styles, col_widths=None):
    out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
           '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">']
    if col_widths:
        out.append('<cols>')
        for i, w in enumerate(col_widths):
            out.append(f'<col min="{i+1}" max="{i+1}" width="{w}" customWidth="1"/>')
        out.append('</cols>')
    out.append('<sheetData>')

    def cell(ci, ri, value, style):
        ref = f"{_col_letter(ci)}{ri}"
        s_attr = f' s="{style}"' if style else ''
        if value is None:
            value = ""
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return f'<c r="{ref}"{s_attr}><v>{value}</v></c>'
        return f'<c r="{ref}"{s_attr} t="inlineStr"><is><t xml:space="preserve">{escape(str(value))}</t></is></c>'

    r = 1
    out.append(f'<row r="{r}">')
    for ci, h in enumerate(headers):
        out.append(cell(ci, r, h, style_index("header")))
    out.append('</row>')
    r += 1
    for row, st in zip(rows, row_styles):
        out.append(f'<row r="{r}">')
        s_idx = style_index(st)
        for ci, v in enumerate(row):
            out.append(cell(ci, r, v, s_idx))
        out.append('</row>')
        r += 1
    out.append('</sheetData></worksheet>')
    return "".join(out)


def write_xlsx(path, sheets):
    """sheets: liste de dicts {name, headers, rows, row_styles?, col_widths?}."""
    content_types = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
                     '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
                     '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
                     '<Default Extension="xml" ContentType="application/xml"/>',
                     '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
                     '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>']
    for i in range(len(sheets)):
        content_types.append(
            f'<Override PartName="/xl/worksheets/sheet{i+1}.xml" '
            f'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
    content_types.append('</Types>')

    root_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>'''

    wb_sheets = "".join(
        f'<sheet name="{escape(s["name"][:31])}" sheetId="{i+1}" r:id="rId{i+1}"/>'
        for i, s in enumerate(sheets))
    workbook_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets>{wb_sheets}</sheets>
</workbook>'''

    wb_rels_items = "".join(
        f'<Relationship Id="rId{i+1}" '
        f'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        f'Target="worksheets/sheet{i+1}.xml"/>'
        for i in range(len(sheets)))
    wb_rels_items += (f'<Relationship Id="rId{len(sheets)+1}" '
                       f'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
                       f'Target="styles.xml"/>')
    workbook_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                      '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                      + wb_rels_items + '</Relationships>')

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "".join(content_types))
        z.writestr("_rels/.rels", root_rels)
        z.writestr("xl/workbook.xml", workbook_xml)
        z.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        z.writestr("xl/styles.xml", _styles_xml())
        for i, s in enumerate(sheets):
            xml = _sheet_xml(s["headers"], s["rows"],
                              s.get("row_styles") or [None] * len(s["rows"]),
                              s.get("col_widths"))
            z.writestr(f"xl/worksheets/sheet{i+1}.xml", xml)


def export_findings_xlsx(findings, path):
    headers = ["Sévérité", "Contrôle", "Titre", "Emplacement", "Recommandation",
               "Référence", "Correctif proposé"]
    rows, styles = [], []
    for f in findings:
        rows.append([f.sev, f.check, f.title, f.where, f.reco, f.ref,
                     " | ".join(f.fix) if f.fix else ""])
        styles.append(f.sev)
    write_xlsx(path, [{
        "name": "Findings",
        "headers": headers,
        "rows": rows,
        "row_styles": styles,
        "col_widths": [11, 20, 40, 45, 55, 20, 60],
    }])

# --------------------------------------------------------------------------- #
# Rapport
# --------------------------------------------------------------------------- #

def count_by_severity(findings):
    counts = {}
    for f in findings:
        counts[f.sev] = counts.get(f.sev, 0) + 1
    return counts


def build_report_text(findings, meta=None):
    """Rapport texte lisible (utilisé en CLI et par l'appli web).

    meta (optionnel) : le dict retourné par parse(), pour afficher le format
    détecté et les avertissements de lecture. Un audit doit dire ce qu'il n'a
    pas su lire, sinon « 0 constat » est indistinguable de « rien compris ».
    """
    findings = sorted(findings, key=lambda f: (SEV_RANK[f.sev], f.check, f.where))
    counts = count_by_severity(findings)
    lines = []
    lines.append("=" * 72)
    lines.append("AUDIT DE DURCISSEMENT SRX — REMÉDIATIONS")
    lines.append("=" * 72)
    if meta:
        lines.append(f"Format source détecté : {meta.get('source_format', '?')}")
        warns = meta.get("warnings") or []
        if warns:
            lines.append("")
            lines.append(f"⚠ {len(warns)} AVERTISSEMENT(S) DE LECTURE — "
                         f"l'audit peut être incomplet :")
            for w in warns:
                lines.append(f"    - {w}")
    summary = "  ".join(f"{s}:{counts.get(s,0)}"
                        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
    lines.append(f"Total : {len(findings)}   [{summary}]")
    lines.append("")
    for f in findings:
        lines.append(f"[{f.sev}] {f.check} — {f.title}")
        lines.append(f"    où     : {f.where}")
        lines.append(f"    reco   : {f.reco}")
        lines.append(f"    réf    : {f.ref}")
        if f.fix:
            lines.append(f"    correctif :")
            for c in f.fix:
                lines.append(f"        {c}")
        lines.append("")
    return "\n".join(lines)


def build_findings_json(findings):
    counts = count_by_severity(findings)
    data = [{"severity": f.sev, "check": f.check, "title": f.title,
             "where": f.where, "recommendation": f.reco, "reference": f.ref,
             "fix": f.fix} for f in findings]
    return {"summary": counts, "findings": data}


def build_fix_text(findings):
    out = ["# === correctifs proposés (À RELIRE avant commit) ===",
           "# Les lignes commentées (#) demandent une décision/valeur.",
           "# Charger sous 'configure private' puis 'commit check'.", ""]
    for f in findings:
        if not f.fix:
            continue
        out.append(f"# [{f.sev}] {f.check} — {f.where}")
        out.extend(f.fix)
        out.append("")
    return "\n".join(out) + "\n"


def render(findings, fmt_json, fix_path, xlsx_path, report_path=None, meta=None):
    findings.sort(key=lambda f: (SEV_RANK[f.sev], f.check, f.where))
    report = build_report_text(findings, meta)
    print(report)

    if report_path:
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
        print(f"[+] Rapport texte écrit : {report_path}")

    if fmt_json:
        with open(fmt_json, "w", encoding="utf-8") as fh:
            json.dump(build_findings_json(findings), fh, ensure_ascii=False, indent=2)
        print(f"[+] JSON écrit : {fmt_json}")

    if xlsx_path:
        export_findings_xlsx(findings, xlsx_path)
        print(f"[+] Excel écrit : {xlsx_path}")

    if fix_path:
        with open(fix_path, "w", encoding="utf-8") as fh:
            fh.write(build_fix_text(findings))
        print(f"[+] Correctifs écrits : {fix_path}")

# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="srxaudit",
        description="Audit de durcissement d'une configuration Juniper SRX.")
    ap.add_argument("config",
                    help="conf : soit 'show configuration | display xml', "
                         "soit directement 'show configuration' (texte, "
                         "détection automatique du format)")
    ap.add_argument("--json", help="fichier JSON de sortie")
    ap.add_argument("--xlsx", help="fichier Excel (.xlsx) coloré par sévérité")
    ap.add_argument("--fix", help="fichier de correctifs set/delete")
    ap.add_argument("--report", help="fichier texte du rapport")
    ap.add_argument("--min-severity", choices=list(SEV_RANK),
                    default="INFO", help="ne montrer qu'à partir de ce niveau")
    ap.add_argument("--allow-empty", action="store_true",
                    help="accepter une conf dont rien n'a pu être extrait "
                         "(par défaut : erreur, pour ne pas délivrer un rapport "
                         "vide qui ferait croire à une conf saine)")
    args = ap.parse_args(argv)

    try:
        m, units, screens, zones, policies = parse(
            args.config, allow_empty=args.allow_empty)
    except ConfigFormatError as e:
        print(f"[ERREUR] {e}", file=sys.stderr)
        sys.exit(3)

    F = []
    try:
        check_policies(zones, policies, F)
        check_zones(zones, screens, F)
        if m["system"] is not None:
            check_system(m["system"], m["snmp"], F)
    except UnsafeNameError as e:
        print(f"[ERREUR] {e}", file=sys.stderr)
        sys.exit(4)

    thr = SEV_RANK[args.min_severity]
    F = [f for f in F if SEV_RANK[f.sev] <= thr]

    render(F, args.json, args.fix, args.xlsx, args.report, meta=m)

    if any(f.sev == "CRITICAL" for f in F):
        sys.exit(2)
    if any(f.sev == "HIGH" for f in F):
        sys.exit(1)


if __name__ == "__main__":
    main()
