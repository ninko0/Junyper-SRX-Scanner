#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
srxtool — boîte à outils d'analyse de configuration Juniper SRX (stdlib only)

Trois sous-commandes qui s'enchaînent :

  inventory  Parse la conf (XML "display xml" OU texte "show configuration",
             détection automatique du format) et produit le "classement" :
             VLAN -> zone -> adresses -> politiques.
             Sortie JSON réutilisée par les autres commandes, plus en option
             un export Excel (--xlsx) : un classeur avec un onglet VLANs,
             un onglet Zones, un onglet Politiques et un onglet Objets
             d'adresse, avec quelques lignes surlignées (VLAN sans zone L3,
             permit any/any/any) pour repérer vite les points d'attention.

  rename     Détecte les objets d'address-book nommés "en IP" (ex: un objet
             nommé littéralement "10.20.20.50/32"). Deux phases :
               --suggest : écrit un CSV de plan (avec suggestions PTR/contexte)
               --from-map: lit le CSV rempli et génère les commandes set/delete
                           qui créent le nouvel objet, repointent TOUTES les
                           références (policies + address-sets) et suppriment
                           l'ancien.

  cleanup    Croise le classement (JSON d'inventory) avec un export
             "show security policies hit-count | display xml" et génère les
             commandes de suppression des règles jamais matchées (hit-count 0),
             avec garde-fous (deny protégés, reset compteur, motifs exclus) et
             un fichier de rollback reconstruit depuis la conf.

Aucune dépendance externe. Aucune action n'est poussée sur l'équipement :
l'outil n'écrit que des fichiers de commandes à relire puis charger toi-même.
"""

import argparse
import csv
import fnmatch
import ipaddress
import json
import os
import re
import shlex
import sys
import xml.etree.ElementTree as ET
import zipfile
from xml.sax.saxutils import escape

# --------------------------------------------------------------------------- #
# Helpers XML (robustes aux espaces de noms Junos)
# --------------------------------------------------------------------------- #

def ln(tag):
    """Local name d'une balise (retire l'éventuel {namespace})."""
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else tag


def kids(el, name):
    return [c for c in list(el) if ln(c.tag) == name] if el is not None else []


def kid(el, name):
    for c in list(el) if el is not None else []:
        if ln(c.tag) == name:
            return c
    return None


def txt(el, name, default=None):
    c = kid(el, name)
    if c is not None and c.text and c.text.strip():
        return c.text.strip()
    return default


def find_config_root(tree_root):
    """Trouve l'élément <configuration> où qu'il soit (rpc-reply, etc.)."""
    if ln(tree_root.tag) == "configuration":
        return tree_root
    for e in tree_root.iter():
        if ln(e.tag) == "configuration":
            return e
    return tree_root


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


class ConfigFormatError(ValueError):
    """Conf illisible, vide ou de format non reconnu.

    On échoue bruyamment : un audit qui rend « 0 problème » parce qu'il n'a rien
    su lire est plus dangereux qu'une erreur explicite.
    """


def parse_curly_text(text):
    """Parse un 'show configuration' texte (accolades) en arbre générique :
    node = {"children": [(header_tokens, child_node), ...],
            "leaves": [(key, [vals]), ...]}

    Retourne (root, warnings). Toute ligne non interprétée, accolade
    déséquilibrée ou strophe 'inactive:' est signalée dans warnings au lieu
    d'être ignorée en silence.
    """
    root = {"children": [], "leaves": []}
    stack = [root]
    warnings, skipped, inactive = [], 0, 0

    def warn(msg):
        if len(warnings) < 25:
            warnings.append(msg)

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("/*"):
            continue
        if line.startswith("inactive:"):
            inactive += 1
            line = line[len("inactive:"):].strip()
            if not line:
                continue
        if line in ("}", "};"):
            if len(stack) > 1:
                stack.pop()
            else:
                warn(f"ligne {lineno} : accolade fermante en trop (conf malformée)")
            continue
        if line.endswith("{"):
            header = _split_tokens(line[:-1].strip())
            if not header:
                warn(f"ligne {lineno} : bloc sans nom, ignoré")
                continue
            node = {"children": [], "leaves": []}
            stack[-1]["children"].append((header, node))
            stack.append(node)
            continue
        if line.endswith(";"):
            toks = _split_tokens(line[:-1].strip())
            if toks:
                stack[-1]["leaves"].append((toks[0], toks[1:]))
            continue
        skipped += 1
        warn(f"ligne {lineno} non interprétée : {line[:70]!r}")

    if len(stack) > 1:
        warnings.append(f"{len(stack) - 1} bloc(s) jamais refermé(s) : "
                        f"la fin de la conf peut avoir été mal rattachée")
    if skipped:
        warnings.append(f"{skipped} ligne(s) non interprétée(s) au total — "
                        f"résultat potentiellement incomplet")
    if inactive:
        warnings.append(f"{inactive} strophe(s) marquée(s) 'inactive:' ont été "
                        f"analysées comme si elles étaient actives")
    return root, warnings


# Conteneurs Junos qui prennent un nom : "<mot-clé> <nom> { ... }".
# Sert à reconstruire la hiérarchie depuis le format 'display set', où tout
# est aplati sur une ligne.
# Liste volontairement restreinte aux hiérarchies que l'outil lit réellement :
# y mettre un mot-clé de trop casse le regroupement (ex. "vlan" avalerait le
# "members" de 'family ethernet-switching vlan members VLAN10').
_SET_NAMED_CONTAINERS = frozenset({
    "security-zone", "policy", "address", "address-set", "ids-option",
    "community", "unit", "family", "host", "instance", "rule", "rule-set",
})


def parse_set_text(text):
    """Parse une conf au format 'show configuration | display set'
    (une commande 'set ...' par ligne) et produit le même arbre générique que
    parse_curly_text(). Retourne (root, warnings).

    C'était le trou noir de la version précédente : ces lignes ne finissant ni
    par '{' ni par ';', elles étaient toutes jetées et l'audit rendait
    « 0 constat » sur une conf pourtant vulnérable.
    """
    root = {"children": [], "leaves": []}
    warnings, skipped, deactivated = [], 0, 0

    def warn(msg):
        if len(warnings) < 25:
            warnings.append(msg)

    def descend(node, header):
        for h, c in node["children"]:
            if h == header:
                return c
        c = {"children": [], "leaves": []}
        node["children"].append((header, c))
        return c

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        toks = _split_tokens(line)
        if not toks:
            continue
        if toks[0] == "deactivate":
            deactivated += 1
            continue
        if toks[0] != "set":
            skipped += 1
            warn(f"ligne {lineno} ignorée (ne commence pas par 'set') : {line[:70]!r}")
            continue

        toks = toks[1:]
        node, i, n = root, 0, len(toks)
        if n == 0:
            warn(f"ligne {lineno} : 'set' sans argument")
            continue
        while i < n:
            t = toks[i]
            # "from-zone A to-zone B" = un seul bloc à 4 tokens
            if t == "from-zone" and i + 3 < n and toks[i + 2] == "to-zone":
                node = descend(node, toks[i:i + 4])
                i += 4
                continue
            if i == n - 1:                      # dernier token -> identifiant nu
                node["leaves"].append((t, []))
                i += 1
                continue
            if t in _SET_NAMED_CONTAINERS:      # "<mot-clé> <nom>"
                node = descend(node, [t, toks[i + 1]])
                i += 2
                continue
            node = descend(node, [t])
            i += 1

    if skipped:
        warnings.append(f"{skipped} ligne(s) non interprétée(s) au total — "
                        f"résultat potentiellement incomplet")
    if deactivated:
        warnings.append(f"{deactivated} ligne(s) 'deactivate' ignorée(s) : la "
                        f"strophe correspondante est analysée comme active")
    return root, warnings


def looks_like_xml(text):
    return text.lstrip()[:200].startswith("<")


def looks_like_set_format(text):
    """Vrai si la conf est au format 'display set' (majorité de lignes 'set ')."""
    setlines = other = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("set ") or line.startswith("delete ") \
                or line.startswith("deactivate "):
            setlines += 1
        else:
            other += 1
        if setlines + other > 400:
            break
    return setlines > 0 and setlines >= max(3, other)


def parse_text_auto(text):
    """Choisit le bon parseur texte (accolades ou 'display set').
    Retourne (root, warnings, format_name)."""
    if looks_like_set_format(text):
        root, warnings = parse_set_text(text)
        return root, warnings, "set"
    root, warnings = parse_curly_text(text)
    return root, warnings, "curly"


def cchildren(node, key):
    if node is None:
        return []
    return [(h[1:], c) for h, c in node["children"] if h and h[0] == key]

def cchild(node, key):
    r = cchildren(node, key)
    return r[0][1] if r else None

def _bare_names(node):
    """Identifiants nus d'un bloc : feuilles sans valeur + en-têtes mono-token."""
    if node is None:
        return []
    out = [k for k, v in node["leaves"] if not v]
    out += [h[0] for h, c in node["children"] if len(h) == 1]
    return out

def cbare_value(node):
    """Valeur unique d'un bloc exprimé 'clé { valeur; }' (typique du format set)."""
    if node is None:
        return None
    names = _bare_names(node)
    return names[0] if len(names) == 1 else None

def cleaf(node, key, default=None):
    """Valeur d'une clé, quelle que soit la forme retenue par la conf :
       'clé valeur;'  |  'clé { valeur; }'  |  'clé valeur { ... }'
    (les deux dernières formes proviennent du format 'display set')."""
    if node is None:
        return default
    for k, v in node["leaves"]:
        if k == key:
            return " ".join(v) if v else True
    for h, c in node["children"]:
        if h and h[0] == key:
            if len(h) > 1:
                return " ".join(h[1:])
            val = cbare_value(c)
            return val if val is not None else True
    return default

def cvalues(node, key):
    """Toutes les valeurs associées à une clé, quelle que soit la forme :
       'clé v;'  |  'clé [ v1 v2 ];'  |  'clé { v1; v2; }'  |  'clé v1; clé v2;'

    Unifie les trois écritures possibles. L'ancienne version ne lisait que la
    première, ce qui faisait manquer en silence les listes entre crochets
    (ex. 'system-services [ ping ssh ];').
    """
    if node is None:
        return []
    out = []
    for k, v in node["leaves"]:
        if k == key:
            out.extend(v)
    for h, c in node["children"]:
        if h and h[0] == key:
            out.extend(h[1:])
            out.extend(_bare_names(c))
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq

# Conservé pour compatibilité : même comportement que cvalues désormais.
cleaf_all = cvalues

def chas(node, key):
    if node is None:
        return False
    if any(k == key for k, v in node["leaves"]):
        return True
    return any(h and h[0] == key for h, c in node["children"])

def cbare_names(node):
    if node is None:
        return []
    names = [k for k, v in node["leaves"]]
    names += [h[0] for h, c in node["children"] if h]
    return names


# --------------------------------------------------------------------------- #
# Parsing de la configuration (XML)
# --------------------------------------------------------------------------- #

def parse_address_book_body(ab):
    """Retourne (addresses{name:prefix}, sets{name:{'addresses':[], 'address_sets':[]}})."""
    addresses, sets_ = {}, {}
    if ab is None:
        return addresses, sets_
    for a in kids(ab, "address"):
        an = txt(a, "name")
        if an is None:
            continue
        pfx = txt(a, "ip-prefix")
        if pfx is None:
            dn = kid(a, "dns-name")
            if dn is not None:
                pfx = "dns:" + (txt(dn, "name") or "")
            rng = kid(a, "range-address")
            if rng is not None:
                pfx = "range:" + (txt(rng, "name") or "")
        addresses[an] = pfx
    for s in kids(ab, "address-set"):
        sn = txt(s, "name")
        if sn is None:
            continue
        mem = [txt(m, "name") for m in kids(s, "address") if txt(m, "name")]
        smem = [txt(m, "name") for m in kids(s, "address-set") if txt(m, "name")]
        sets_[sn] = {"addresses": mem, "address_sets": smem}
    return addresses, sets_


def addr_ref(el):
    """Valeur d'une référence d'adresse dans une policy (name ou texte 'any')."""
    n = txt(el, "name")
    if n:
        return n
    return el.text.strip() if el.text and el.text.strip() else None


def parse_config_xml(path):
    tree = ET.parse(path)
    conf = find_config_root(tree.getroot())

    units = {}
    interfaces_el = kid(conf, "interfaces")
    for itf in kids(interfaces_el, "interface"):
        iname = txt(itf, "name")
        for unit in kids(itf, "unit"):
            uname = txt(unit, "name")
            full = f"{iname}.{uname}"
            fam = kid(unit, "family")
            inet_addrs, vlan_members = [], []
            if fam is not None:
                inet = kid(fam, "inet")
                for addr in kids(inet, "address"):
                    a = txt(addr, "name")
                    if a:
                        inet_addrs.append(a)
                eth = kid(fam, "ethernet-switching")
                if eth is not None:
                    vlan = kid(eth, "vlan")
                    for m in kids(vlan, "members"):
                        if m.text and m.text.strip():
                            vlan_members.append(m.text.strip())
            units[full] = {
                "interface": iname,
                "unit": uname,
                "inet": inet_addrs,
                "vlan_members": vlan_members,
            }

    vlans = {}
    vlans_el = kid(conf, "vlans")
    for v in kids(vlans_el, "vlan"):
        vname = txt(v, "name")
        if vname is None:
            continue
        vlans[vname] = {
            "vlan_id": txt(v, "vlan-id"),
            "l3_interface": txt(v, "l3-interface"),
            "members": [],
        }
    for full, u in units.items():
        for vm in u["vlan_members"]:
            if vm in vlans:
                vlans[vm]["members"].append(full)

    sec = kid(conf, "security")
    zones = {}
    zel = kid(sec, "zones")
    for z in kids(zel, "security-zone"):
        zn = txt(z, "name")
        ifaces = [txt(i, "name") for i in kids(z, "interfaces") if txt(i, "name")]
        ab = kid(z, "address-book")
        addrs, sets_ = parse_address_book_body(ab)
        zones[zn] = {
            "interfaces": ifaces,
            "legacy_book": {"addresses": addrs, "address_sets": sets_} if ab is not None else None,
            "vlans": [],
            "policies_from": [],
            "policies_to": [],
        }

    global_books = {}
    for ab in kids(sec, "address-book"):
        bn = txt(ab, "name") or "global"
        addrs, sets_ = parse_address_book_body(ab)
        attach = kid(ab, "attach")
        zlist = []
        if attach is not None:
            for zt in kids(attach, "zone"):
                zn = txt(zt, "name") or (zt.text.strip() if zt.text else None)
                if zn:
                    zlist.append(zn)
        global_books[bn] = {"addresses": addrs, "address_sets": sets_, "zones": zlist}

    policies = []
    pol_root = kid(sec, "policies")
    for pblock in kids(pol_root, "policy"):
        fz = txt(pblock, "from-zone-name")
        tz = txt(pblock, "to-zone-name")
        for pol in kids(pblock, "policy"):
            pn = txt(pol, "name")
            match = kid(pol, "match")
            src = [addr_ref(x) for x in kids(match, "source-address")]
            dst = [addr_ref(x) for x in kids(match, "destination-address")]
            apps = [addr_ref(x) for x in kids(match, "application")]
            src = [x for x in src if x]
            dst = [x for x in dst if x]
            apps = [x for x in apps if x]
            then = kid(pol, "then")
            action, flags = None, []
            if then is not None:
                for c in list(then):
                    nm = ln(c.tag)
                    if nm in ("permit", "deny", "reject"):
                        action = nm
                    elif nm == "log":
                        for lc in list(c):
                            flags.append("log " + ln(lc.tag))
                    elif nm == "count":
                        flags.append("count")
            policies.append({
                "from_zone": fz, "to_zone": tz, "name": pn,
                "source": src or ["any"], "destination": dst or ["any"],
                "application": apps or ["any"],
                "action": action or "permit", "flags": flags,
            })

    return _finalize_model(units, vlans, zones, global_books, policies)


# --------------------------------------------------------------------------- #
# Parsing de la configuration (texte "show configuration")
# --------------------------------------------------------------------------- #

def parse_address_book_body_text(ab):
    addresses, sets_ = {}, {}
    if ab is None:
        return addresses, sets_
    for h, a in cchildren(ab, "address"):
        an = h[0] if h else None
        if an is None:
            continue
        pfx = cleaf(a, "ip-prefix")
        if pfx is None:
            dn = cchild(a, "dns-name")
            if dn is not None:
                pfx = "dns:" + (cbare_value(dn) or "")
            rng = cchild(a, "range-address")
            if rng is not None:
                pfx = "range:" + (cbare_value(rng) or "")
        if pfx is None:
            # format 'display set' : "address NAME PREFIX" -> address { NAME { PREFIX; } }
            pfx = cbare_value(a)
        addresses[an] = pfx
    # forme leaf directe : "address NAME PREFIX;" (pas de sous-bloc)
    for k, v in ab["leaves"]:
        if k == "address" and len(v) >= 2:
            addresses[v[0]] = v[1]
    for h, s in cchildren(ab, "address-set"):
        sn = h[0] if h else None
        if sn is None:
            continue
        sets_[sn] = {"addresses": cvalues(s, "address"),
                     "address_sets": cvalues(s, "address-set")}
    return addresses, sets_


def parse_config_text(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    root, warnings, fmt = parse_text_auto(text)

    units = {}
    interfaces_el = cchild(root, "interfaces")
    for ih, itf in (interfaces_el["children"] if interfaces_el else []):
        iname = ih[0] if ih else None
        if not iname:
            continue
        for uh, unit in cchildren(itf, "unit"):
            uname = uh[0] if uh else None
            full = f"{iname}.{uname}"
            # "family inet { ... }" / "family ethernet-switching { ... }" sont
            # CHACUN un bloc dont le header est ["family", "inet"] ou
            # ["family", "ethernet-switching"] (pas un bloc "family" imbriquant
            # un sous-bloc "inet").
            inet_addrs, vlan_members = [], []
            for rest, fnode in cchildren(unit, "family"):
                if rest and rest[0] == "inet":
                    inet_addrs.extend(cvalues(fnode, "address"))
                elif rest and rest[0] == "ethernet-switching":
                    vlan = cchild(fnode, "vlan")
                    if vlan is not None:
                        vlan_members.extend(cvalues(vlan, "members"))
            units[full] = {
                "interface": iname,
                "unit": uname,
                "inet": inet_addrs,
                "vlan_members": vlan_members,
            }

    vlans = {}
    vlans_el = cchild(root, "vlans")
    for vh, v in (vlans_el["children"] if vlans_el else []):
        vname = vh[0] if vh else None
        if vname is None:
            continue
        vlans[vname] = {
            "vlan_id": cleaf(v, "vlan-id"),
            "l3_interface": cleaf(v, "l3-interface"),
            "members": [],
        }
    for full, u in units.items():
        for vm in u["vlan_members"]:
            if vm in vlans:
                vlans[vm]["members"].append(full)

    sec = cchild(root, "security")
    zones = {}
    zel = cchild(sec, "zones")
    for h, z in cchildren(zel, "security-zone"):
        zn = h[0] if h else None
        if not zn:
            continue
        ifaces = cbare_names(cchild(z, "interfaces"))
        ab = cchild(z, "address-book")
        addrs, sets_ = parse_address_book_body_text(ab)
        zones[zn] = {
            "interfaces": ifaces,
            "legacy_book": {"addresses": addrs, "address_sets": sets_} if ab is not None else None,
            "vlans": [],
            "policies_from": [],
            "policies_to": [],
        }

    global_books = {}
    for h, ab in cchildren(sec, "address-book"):
        bn = h[0] if h else "global"
        addrs, sets_ = parse_address_book_body_text(ab)
        attach = cchild(ab, "attach")
        zlist = cvalues(attach, "zone") if attach is not None else []
        global_books[bn] = {"addresses": addrs, "address_sets": sets_, "zones": zlist}

    policies = []
    pol_root = cchild(sec, "policies")
    for h, pblock in (pol_root["children"] if pol_root else []):
        if not (len(h) >= 4 and h[0] == "from-zone" and h[2] == "to-zone"):
            continue
        fz, tz = h[1], h[3]
        for ph, pol in cchildren(pblock, "policy"):
            pn = ph[0] if ph else None
            match = cchild(pol, "match")
            src = cvalues(match, "source-address")
            dst = cvalues(match, "destination-address")
            apps = cvalues(match, "application")
            then = cchild(pol, "then")
            action, flags = None, []
            if then is not None:
                for k, v in then["leaves"]:
                    if k in ("permit", "deny", "reject"):
                        action = k
                    elif k == "log":
                        flags.append("log " + (v[0] if v else ""))
                    elif k == "count":
                        flags.append("count")
                for th, tc in then["children"]:
                    if th and th[0] in ("permit", "deny", "reject"):
                        action = th[0]
                    if th and th[0] == "log":
                        for lg in cbare_names(tc):
                            flags.append("log " + lg)
                    if th and th[0] == "count":
                        flags.append("count")
            policies.append({
                "from_zone": fz, "to_zone": tz, "name": pn,
                "source": src or ["any"], "destination": dst or ["any"],
                "application": apps or ["any"],
                "action": action or "permit", "flags": flags,
            })

    model = _finalize_model(units, vlans, zones, global_books, policies)
    model["warnings"] = warnings
    model["source_format"] = fmt
    return model


def _finalize_model(units, vlans, zones, global_books, policies):
    if2zone = {}
    for zn, z in zones.items():
        for i in z["interfaces"]:
            if2zone[i] = zn

    for vn, v in vlans.items():
        l3 = v.get("l3_interface")
        v["zone"] = if2zone.get(l3) if l3 else None
        v["l3_addresses"] = units.get(l3, {}).get("inet", []) if l3 else []

    for zn, z in zones.items():
        z["vlans"] = [vn for vn, v in vlans.items() if v.get("zone") == zn]
        z["policies_from"] = [f"{p['from_zone']}->{p['to_zone']}:{p['name']}"
                              for p in policies if p["from_zone"] == zn]
        z["policies_to"] = [f"{p['from_zone']}->{p['to_zone']}:{p['name']}"
                            for p in policies if p["to_zone"] == zn]

    return {
        "units": units,
        "vlans": vlans,
        "zones": zones,
        "global_books": global_books,
        "policies": policies,
        "warnings": [],
        "source_format": "xml",
    }


def assert_model_not_empty(model, path, allow_empty=False):
    """Refuse un modèle vide : si on n'a lu ni zone, ni policy, ni interface, ni
    VLAN, c'est que le format n'a pas été reconnu — pas que l'équipement est nu.

    Rendre un rapport vide dans ce cas ferait croire à une configuration saine :
    c'est le pire résultat possible pour un outil d'audit.
    """
    if allow_empty:
        return model
    if (model["zones"] or model["policies"] or model["units"] or model["vlans"]):
        return model
    fmt = model.get("source_format", "?")
    raise ConfigFormatError(
        f"aucune donnée exploitable extraite de {os.path.basename(path)!r} "
        f"(format détecté : {fmt}). Ni zone, ni politique, ni interface, ni VLAN "
        f"n'a été lu — le fichier n'est probablement pas une configuration SRX, "
        f"ou son format n'est pas supporté. "
        f"Formats acceptés : 'show configuration' (accolades), "
        f"'show configuration | display set', 'show configuration | display xml'. "
        f"Utilise --allow-empty pour passer outre.")


def parse_config(path, allow_empty=False):
    with open(path, encoding="utf-8", errors="replace") as fh:
        head = fh.read(500)
    if looks_like_xml(head):
        model = parse_config_xml(path)
    else:
        model = parse_config_text(path)
    return assert_model_not_empty(model, path, allow_empty)


# --------------------------------------------------------------------------- #
# Index des objets d'adresses et de leurs références
# --------------------------------------------------------------------------- #

def build_address_index(model):
    """
    Retourne une liste d'objets d'adresse consolidés :
      {name, prefix, book, book_type('global'|'zone'), zones:[...]}
    et un index name -> usages.
    """
    objs = {}   # (book,name) -> obj  (le name est unique par book)
    name_books = {}  # name -> set(book) pour repérage rapide

    for bn, b in model["global_books"].items():
        for name, pfx in b["addresses"].items():
            objs[(bn, name)] = {"name": name, "prefix": pfx, "book": bn,
                                "book_type": "global", "zones": list(b["zones"])}
            name_books.setdefault(name, set()).add(bn)

    for zn, z in model["zones"].items():
        lb = z.get("legacy_book")
        if not lb:
            continue
        for name, pfx in lb["addresses"].items():
            objs[(zn, name)] = {"name": name, "prefix": pfx, "book": zn,
                                "book_type": "zone", "zones": [zn]}
            name_books.setdefault(name, set()).add(zn)

    usages = {}  # name -> list of usage dicts
    for p in model["policies"]:
        for s in p["source"]:
            if s and s not in ("any", "any-ipv4", "any-ipv6"):
                usages.setdefault(s, []).append(
                    {"kind": "policy-src", "from_zone": p["from_zone"],
                     "to_zone": p["to_zone"], "policy": p["name"],
                     "apps": p["application"]})
        for d in p["destination"]:
            if d and d not in ("any", "any-ipv4", "any-ipv6"):
                usages.setdefault(d, []).append(
                    {"kind": "policy-dst", "from_zone": p["from_zone"],
                     "to_zone": p["to_zone"], "policy": p["name"],
                     "apps": p["application"]})

    def scan_sets(book_name, sets_, book_type):
        for sn, s in sets_.items():
            for m in s["addresses"]:
                usages.setdefault(m, []).append(
                    {"kind": "address-set", "book": book_name,
                     "book_type": book_type, "set": sn})

    for bn, b in model["global_books"].items():
        scan_sets(bn, b["address_sets"], "global")
    for zn, z in model["zones"].items():
        if z.get("legacy_book"):
            scan_sets(zn, z["legacy_book"]["address_sets"], "zone")

    return objs, usages


# --------------------------------------------------------------------------- #
# Détection "objet nommé en IP"
# --------------------------------------------------------------------------- #

_IP_NAME_RE = re.compile(
    r"^(?:[A-Za-z]{1,6}[-_])?"                 # préfixe optionnel h-, host_, net_, addr_
    r"(\d{1,3}(?:\.\d{1,3}){3})"               # l'IP
    r"(?:[/_-](\d{1,2}))?$"                    # /masque optionnel (/, _ ou -)
)


def ip_named(name, prefix=None):
    """
    Si l'objet est nommé "en IP" (peu parlant), retourne l'IP/prefix détecté,
    sinon None. Reconnaît aussi le cas name == prefix.
    """
    n = name.strip()
    if prefix and n == prefix:
        try:
            ipaddress.ip_network(prefix, strict=False)
            return prefix
        except ValueError:
            pass
    m = _IP_NAME_RE.match(n)
    if not m:
        return None
    ip = m.group(1)
    if not all(0 <= int(o) <= 255 for o in ip.split(".")):
        return None
    mask = m.group(2)
    return f"{ip}/{mask}" if mask else ip


# --------------------------------------------------------------------------- #
# Suggestion de nom (contexte applicatif + PTR optionnel)
# --------------------------------------------------------------------------- #

_APP_HINTS = [
    (("https", "443", "junos-https"), "web"),
    (("http", "80", "junos-http"), "web"),
    (("ssh", "22", "junos-ssh"), "ssh"),
    (("rdp", "3389", "junos-ms-rdp", "junos-rdp"), "rdp"),
    (("mysql", "3306", "junos-mysql"), "db"),
    (("mssql", "1433", "junos-ms-sql", "ms-sql"), "db"),
    (("ldap", "389", "junos-ldap", "ldaps", "636"), "ldap"),
    (("dns", "53", "junos-dns-tcp", "junos-dns-udp"), "dns"),
    (("smtp", "25", "junos-smtp"), "mail"),
    (("smb", "445", "junos-smb", "cifs"), "file"),
    (("ntp", "123", "junos-ntp"), "ntp"),
    (("snmp", "161", "junos-snmp"), "snmp"),
    (("syslog", "514", "junos-syslog"), "log"),
]


def app_role(apps):
    joined = " ".join(a.lower() for a in apps)
    for keys, role in _APP_HINTS:
        if any(k in joined for k in keys):
            return role
    return None


def ptr_lookup(ip):
    import socket
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None


def suggest_name(ip_prefix, zone_hint, usages, use_dns=False):
    ip = ip_prefix.split("/")[0]
    last_octet = ip.split(".")[-1]

    if use_dns:
        host = ptr_lookup(ip)
        if host:
            label = host.split(".")[0]
            label = re.sub(r"[^A-Za-z0-9_-]", "-", label)
            return label

    apps = []
    for u in usages or []:
        if u.get("kind") == "policy-dst":
            apps.extend(u.get("apps", []))
    role = app_role(apps)

    zpart = (zone_hint or "srv").lower()
    if role:
        return f"{zpart}-{role}-{last_octet}"
    return f"{zpart}-host-{last_octet}"


# --------------------------------------------------------------------------- #
# Génération de set-commands
# --------------------------------------------------------------------------- #

class UnsafeNameError(ValueError):
    """Nom refusé parce qu'il pourrait altérer la commande générée."""


# Nom « tranquille » : peut être inséré tel quel dans une commande Junos.
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,62}$")

# Caractères qui, dans un nom, permettraient d'injecter une instruction :
# retour à la ligne (nouvelle commande), ';' (fin de strophe), '{'/'}' (bloc).
_NAME_INJECTION_RE = re.compile(r"[\r\n;{}]")


def q(name):
    """Quote défensivement un nom issu de la configuration avant de l'insérer
    dans une commande 'set'/'delete'.

    Sans ça, un nom contenant des espaces (Junos l'autorise, entre guillemets)
    se retrouve éclaté en plusieurs tokens : une policy nommée
    'BENIGN match source-address any' produisait une commande qui ÉLARGISSAIT
    une autre policy au lieu de corriger la bonne.

    Les noms contenant des caractères permettant d'injecter une instruction
    sont refusés — on ne peut pas les rendre sûrs par simple quoting.
    """
    if name is None:
        return '""'
    name = str(name)
    if _NAME_INJECTION_RE.search(name):
        raise UnsafeNameError(
            f"nom refusé (contient un retour à la ligne, ';' ou une accolade, "
            f"ce qui injecterait une instruction dans la commande) : {name!r}")
    if _SAFE_NAME_RE.match(name):
        return name
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def validate_new_name(name, context=""):
    """Valide strictement un nom fourni par l'opérateur (colonne 'new_name' du
    CSV de rename). Contrairement à q(), on refuse tout ce qui n'est pas un
    identifiant simple : ce fichier est destiné à être chargé sur le pare-feu,
    ce n'est pas l'endroit pour accepter de l'exotisme.
    """
    if name is None or not _SAFE_NAME_RE.match(str(name)):
        raise UnsafeNameError(
            f"'new_name' invalide{context} : {name!r}. Attendu : 1 à 63 "
            f"caractères parmi [A-Za-z0-9_.:/@+-], commençant par une lettre "
            f"ou un chiffre.")
    return str(name)


def addr_create_line(obj, name, prefix):
    if obj["book_type"] == "global":
        return (f"set security address-book {q(obj['book'])} "
                f"address {q(name)} {q(prefix)}")
    return (f"set security zones security-zone {q(obj['book'])} "
            f"address-book address {q(name)} {q(prefix)}")


def addr_delete_line(obj, name):
    if obj["book_type"] == "global":
        return f"delete security address-book {q(obj['book'])} address {q(name)}"
    return (f"delete security zones security-zone {q(obj['book'])} "
            f"address-book address {q(name)}")


def set_ref_lines(usage, old, new):
    """Commandes set (nouveau) + delete (ancien) pour une référence donnée."""
    k = usage["kind"]
    if k in ("policy-src", "policy-dst"):
        field = "source-address" if k == "policy-src" else "destination-address"
        base = (f"security policies from-zone {q(usage['from_zone'])} "
                f"to-zone {q(usage['to_zone'])} policy {q(usage['policy'])} "
                f"match {field}")
        return [f"set {base} {q(new)}", f"delete {base} {q(old)}"]
    if k == "address-set":
        if usage["book_type"] == "global":
            base = (f"security address-book {q(usage['book'])} "
                    f"address-set {q(usage['set'])} address")
        else:
            base = (f"security zones security-zone {q(usage['book'])} "
                    f"address-book address-set {q(usage['set'])} address")
        return [f"set {base} {q(new)}", f"delete {base} {q(old)}"]
    return []


def policy_set_lines(p):
    base = (f"set security policies from-zone {q(p['from_zone'])} "
            f"to-zone {q(p['to_zone'])} policy {q(p['name'])}")
    lines = []
    for s in p["source"]:
        lines.append(f"{base} match source-address {q(s)}")
    for d in p["destination"]:
        lines.append(f"{base} match destination-address {q(d)}")
    for a in p["application"]:
        lines.append(f"{base} match application {q(a)}")
    lines.append(f"{base} then {q(p['action'])}")
    for f in p.get("flags", []):
        # flags = "log session-close" / "count" : mots-clés, quotés token par token
        lines.append(f"{base} then " + " ".join(q(t) for t in str(f).split()))
    return lines


def policy_delete_line(p):
    return (f"delete security policies from-zone {q(p['from_zone'])} "
            f"to-zone {q(p['to_zone'])} policy {q(p['name'])}")


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


def export_inventory_xlsx(model, zone_objects, path):
    # --- onglet VLANs ---
    vlan_headers = ["VLAN", "VLAN ID", "Interface L3", "Zone", "Subnet(s)",
                     "Membres (ports)", "Statut"]
    vlan_rows, vlan_styles = [], []
    for vn, v in sorted(model["vlans"].items()):
        zone = v.get("zone") or ""
        statut = "OK" if v.get("zone") else "SANS ZONE L3"
        vlan_rows.append([vn, v.get("vlan_id") or "", v.get("l3_interface") or "",
                           zone, ", ".join(v.get("l3_addresses") or []) or "-",
                           ", ".join(v.get("members") or []) or "-", statut])
        vlan_styles.append("ORPHAN" if not v.get("zone") else "OK")

    # --- onglet Zones ---
    zone_headers = ["Zone", "Interfaces", "VLANs", "Objets d'adresse",
                     "Policies (source)", "Policies (destination)"]
    zone_rows, zone_styles = [], []
    for zn, z in sorted(model["zones"].items()):
        objs_here = sorted(set(zone_objects.get(zn, [])))
        zone_rows.append([zn, ", ".join(z["interfaces"]) or "-",
                           ", ".join(z["vlans"]) or "-",
                           ", ".join(objs_here) or "-",
                           len(z["policies_from"]), len(z["policies_to"])])
        zone_styles.append(None)

    # --- onglet Policies ---
    pol_headers = ["From-zone", "To-zone", "Policy", "Source", "Destination",
                   "Application", "Action", "Flags"]
    pol_rows, pol_styles = [], []
    for p in model["policies"]:
        src_any = "any" in p["source"] or "any-ipv4" in p["source"]
        dst_any = "any" in p["destination"] or "any-ipv4" in p["destination"]
        app_any = "any" in p["application"]
        style = None
        if p["action"] == "permit" and src_any and dst_any and app_any:
            style = "CRITICAL"
        elif p["action"] == "permit" and app_any:
            style = "HIGH"
        elif p["action"] == "permit" and src_any and dst_any:
            style = "MEDIUM"
        pol_rows.append([p["from_zone"], p["to_zone"], p["name"],
                          ", ".join(p["source"]), ", ".join(p["destination"]),
                          ", ".join(p["application"]), p["action"],
                          ", ".join(p.get("flags", [])) or "-"])
        pol_styles.append(style)

    # --- onglet Objets d'adresse ---
    addr_headers = ["Nom", "Préfixe/valeur", "Book", "Type de book",
                     "Zones", "Références"]
    addr_rows, addr_styles = [], []
    for a in model.get("_address_objects", []):
        addr_rows.append([a["name"], a["prefix"] or "", a["book"], a["book_type"],
                           ", ".join(a["zones"]), a["references"]])
        addr_styles.append("ORPHAN" if a["references"] == 0 else None)

    write_xlsx(path, [
        {"name": "VLANs", "headers": vlan_headers, "rows": vlan_rows,
         "row_styles": vlan_styles, "col_widths": [14, 10, 16, 14, 30, 30, 16]},
        {"name": "Zones", "headers": zone_headers, "rows": zone_rows,
         "row_styles": zone_styles, "col_widths": [16, 30, 20, 40, 18, 22]},
        {"name": "Policies", "headers": pol_headers, "rows": pol_rows,
         "row_styles": pol_styles, "col_widths": [14, 14, 22, 30, 30, 20, 10, 20]},
        {"name": "Objets adresse", "headers": addr_headers, "rows": addr_rows,
         "row_styles": addr_styles, "col_widths": [24, 22, 18, 12, 24, 12]},
    ])


# --------------------------------------------------------------------------- #
# Sous-commande : inventory
# --------------------------------------------------------------------------- #

def build_inventory_model(config_path, allow_empty=False):
    """Parse + construit tout ce qu'il faut pour le rapport/JSON/xlsx d'inventory.
    Retourne (model, zone_objects, address_objects, out_json_dict)."""
    model = parse_config(config_path, allow_empty=allow_empty)
    objs, usages = build_address_index(model)

    zone_objects = {zn: [] for zn in model["zones"]}
    for (book, name), o in objs.items():
        for zn in o["zones"]:
            zone_objects.setdefault(zn, []).append(name)

    address_objects = [
        {"name": o["name"], "prefix": o["prefix"], "book": o["book"],
         "book_type": o["book_type"], "zones": o["zones"],
         "references": len(usages.get(o["name"], []))}
        for o in objs.values()
    ]
    model["_address_objects"] = address_objects

    out = {
        "source_format": model.get("source_format"),
        "warnings": model.get("warnings", []),
        "vlans": model["vlans"],
        "zones": model["zones"],
        "policies": model["policies"],
        "address_objects": address_objects,
    }
    return model, zone_objects, address_objects, out


def build_inventory_report_text(model, zone_objects):
    lines = []
    lines.append("=" * 70)
    lines.append("INVENTAIRE SRX — VLAN / ZONE / ADRESSES / POLITIQUES")
    lines.append("=" * 70)
    lines.append(f"Format source détecté : {model.get('source_format', '?')}")
    warns = model.get("warnings") or []
    if warns:
        lines.append("")
        lines.append(f"⚠ {len(warns)} AVERTISSEMENT(S) DE LECTURE — "
                     f"l'inventaire peut être incomplet :")
        for w in warns:
            lines.append(f"    - {w}")
    lines.append("")
    for zn, z in sorted(model["zones"].items()):
        lines.append("")
        lines.append(f"ZONE  {zn}")
        lines.append(f"  interfaces : {', '.join(z['interfaces']) or '(aucune)'}")
        if z["vlans"]:
            lines.append("  VLANs :")
            for vn in z["vlans"]:
                v = model["vlans"][vn]
                subnet = ", ".join(v["l3_addresses"]) or "-"
                mem = ", ".join(v["members"]) or "-"
                lines.append(f"    - {vn} (id {v['vlan_id']}, {v['l3_interface']}) "
                             f"subnet {subnet} | ports {mem}")
        else:
            lines.append("  VLANs : (aucun VLAN L3 rattaché à cette zone)")
        objs_here = sorted(set(zone_objects.get(zn, [])))
        lines.append(f"  objets d'adresse ({len(objs_here)}) : "
                     f"{', '.join(objs_here) or '(aucun)'}")
        pf = z["policies_from"]
        pt = z["policies_to"]
        lines.append(f"  politiques (source) : {len(pf)}")
        for x in pf:
            lines.append(f"      -> {x}")
        lines.append(f"  politiques (destination) : {len(pt)}")
        for x in pt:
            lines.append(f"      <- {x}")

    orphan = [vn for vn, v in model["vlans"].items() if not v.get("zone")]
    if orphan:
        lines.append("")
        lines.append("VLANs sans zone L3 (à vérifier) : " + ", ".join(orphan))

    return "\n".join(lines)


def cmd_inventory(args):
    model, zone_objects, address_objects, out = build_inventory_model(
        args.config, allow_empty=getattr(args, "allow_empty", False))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False, indent=2)
        print(f"[+] Classement JSON écrit : {args.json}")

    if args.xlsx:
        export_inventory_xlsx(model, zone_objects, args.xlsx)
        print(f"[+] Classement Excel écrit : {args.xlsx}")

    report = build_inventory_report_text(model, zone_objects)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
        print(f"[+] Rapport texte écrit : {args.report}")
    if not args.quiet:
        print(report)


# --------------------------------------------------------------------------- #
# Sous-commande : rename
# --------------------------------------------------------------------------- #

def build_subnet_zone_map(model):
    """Liste (réseau, zone) déduite des interfaces L3 des VLANs, pour situer une IP."""
    nets = []
    for vn, v in model["vlans"].items():
        zn = v.get("zone")
        if not zn:
            continue
        for a in v.get("l3_addresses", []):
            try:
                nets.append((ipaddress.ip_network(a, strict=False), zn))
            except ValueError:
                pass
    return nets


def zone_for_ip(ip, subnet_zones):
    try:
        addr = ipaddress.ip_address(ip.split("/")[0])
    except ValueError:
        return None
    for net, zn in subnet_zones:
        if addr in net:
            return zn
    return None


def cmd_rename(args):
    model = parse_config(args.config,
                         allow_empty=getattr(args, "allow_empty", False))
    objs, usages = build_address_index(model)
    subnet_zones = build_subnet_zone_map(model)

    detected = []
    for (book, name), o in objs.items():
        ip = ip_named(name, o["prefix"])
        if not ip:
            continue
        u = usages.get(name, [])
        apps = sorted({a for x in u for a in x.get("apps", []) if a and a != "any"})
        zone_hint = (zone_for_ip(o["prefix"] or ip, subnet_zones)
                     or (o["zones"][0] if o["zones"] else None))
        detected.append({
            "book": book, "book_type": o["book_type"], "old_name": name,
            "prefix": o["prefix"] or ip, "zones": ";".join(o["zones"]),
            "refs": len(u), "apps": ";".join(apps),
            "zone_hint": zone_hint, "usages": u,
        })

    detected.sort(key=lambda d: (d["book"], d["old_name"]))

    if not detected:
        print("[=] Aucun objet nommé en IP détecté.")
        return

    if args.suggest or not args.from_map:
        out_csv = args.output or "rename-plan.csv"
        with open(out_csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["book", "book_type", "old_name", "prefix", "zones",
                        "refs", "apps", "suggested_new_name", "new_name"])
            for d in detected:
                sug = suggest_name(d["prefix"], d["zone_hint"], d["usages"],
                                   use_dns=args.dns)
                w.writerow([d["book"], d["book_type"], d["old_name"], d["prefix"],
                            d["zones"], d["refs"], d["apps"], sug, ""])
        print(f"[+] {len(detected)} objet(s) nommé(s) en IP détecté(s).")
        print(f"[+] Plan écrit : {out_csv}")
        print("    -> Remplis/valide la colonne 'new_name' puis relance avec "
              "--from-map <ce_csv>.")
        print("    (la colonne 'suggested_new_name' est une proposition, "
              "PTR/contexte — à vérifier)")
        return

    mapping = {}
    rejected = []
    with open(args.from_map, newline="", encoding="utf-8") as fh:
        for lineno, row in enumerate(csv.DictReader(fh), start=2):
            new = (row.get("new_name") or "").strip()
            if not new:
                continue
            # Ces noms partent dans un fichier destiné à être chargé sur le
            # pare-feu : on valide strictement au lieu d'interpoler à l'aveugle.
            # Un 'new_name' multi-lignes injectait sinon des commandes
            # arbitraires (ex. 'set system services telnet').
            try:
                new = validate_new_name(new, context=f" (ligne {lineno} du CSV)")
            except UnsafeNameError as e:
                rejected.append(str(e))
                continue
            mapping[(row["book"], row["old_name"])] = new

    if rejected:
        print(f"[!] {len(rejected)} ligne(s) REFUSÉE(S) — aucune commande générée "
              f"pour celles-ci :")
        for r in rejected:
            print(f"    - {r}")

    if not mapping:
        print("[!] Aucune ligne avec 'new_name' valide dans le CSV. Rien à faire.")
        return

    by_key = {(d["book"], d["old_name"]): d for d in detected}
    set_lines, rollback = [], []
    set_lines.append("# --- rename objets IP -> nom de service ---")
    set_lines.append("# À charger sous 'configure private' puis 'commit check'.")
    rollback.append("# --- rollback du rename ---")

    for (book, old), new in mapping.items():
        d = by_key.get((book, old))
        if not d:
            set_lines.append(f"# [ignoré] {book}/{old} introuvable dans la conf")
            continue
        obj = {"book": book, "book_type": d["book_type"]}
        prefix = d["prefix"]
        set_lines.append("")
        set_lines.append(f"# {old}  ->  {new}   ({prefix}, {d['refs']} référence(s))")
        set_lines.append(addr_create_line(obj, new, prefix))
        for u in d["usages"]:
            set_lines.extend(set_ref_lines(u, old, new))
        set_lines.append(addr_delete_line(obj, old))

        rollback.append(f"# {new} -> {old}")
        rollback.append(addr_create_line(obj, old, prefix))
        for u in d["usages"]:
            rollback.extend(set_ref_lines(u, new, old))
        rollback.append(addr_delete_line(obj, new))

    out_set = args.output or "rename.set"
    with open(out_set, "w", encoding="utf-8") as fh:
        fh.write("\n".join(set_lines) + "\n")
    rb = os.path.splitext(out_set)[0] + "-rollback.set"
    with open(rb, "w", encoding="utf-8") as fh:
        fh.write("\n".join(rollback) + "\n")
    print(f"[+] {len(mapping)} renommage(s) généré(s).")
    print(f"[+] Commandes  : {out_set}")
    print(f"[+] Rollback   : {rb}")


# --------------------------------------------------------------------------- #
# Sous-commande : cleanup
# --------------------------------------------------------------------------- #

def parse_hitcount(path):
    """
    Parse 'show security policies hit-count | display xml' (ou son équivalent
    texte 'show security policies hit-count' collé depuis le CLI).
    Retourne dict[(from_zone,to_zone,name)] = {'count':int,'action':str}.
    """
    with open(path, encoding="utf-8", errors="replace") as fh:
        head = fh.read(500)
    if looks_like_xml(head):
        tree = ET.parse(path)
        root = tree.getroot()
        out = {}
        for e in root.iter():
            if ln(e.tag) != "policy-hit-count":
                continue
            fz = tz = name = action = None
            count = 0
            for c in list(e):
                t = ln(c.tag)
                val = c.text.strip() if c.text and c.text.strip() else None
                if t.endswith("from-zone"):
                    fz = val
                elif t.endswith("to-zone"):
                    tz = val
                elif t.endswith("policy-name"):
                    name = val
                elif t.endswith("count"):
                    try:
                        count = int(val)
                    except (TypeError, ValueError):
                        count = 0
                elif t.endswith("policy-action") or t.endswith("action"):
                    action = val
            if name is not None:
                out[(fz, tz, name)] = {"count": count, "action": action}
        return out

    # Format texte CLI, ex :
    #   Policy: allow-any, action:permit
    #     From zone: trust, To zone: untrust
    #     Index: 4, Policy Name: allow-any, State: enabled
    #     Policy order: 1
    #     Number of policy hit: 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    out = {}
    fz = tz = name = action = None
    count = 0
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"Policy:\s*([^,]+),\s*action:\s*(\S+)", line, re.I)
        if m:
            if name is not None:
                out[(fz, tz, name)] = {"count": count, "action": action}
            name, action = m.group(1).strip(), m.group(2).strip()
            fz = tz = None
            count = 0
            continue
        m = re.match(r"From zone:\s*(\S+),\s*To zone:\s*(\S+)", line, re.I)
        if m:
            fz, tz = m.group(1), m.group(2)
            continue
        m = re.search(r"Number of policy hit:\s*(\d+)", line, re.I)
        if m:
            count = int(m.group(1))
            continue
    if name is not None:
        out[(fz, tz, name)] = {"count": count, "action": action}
    return out


def cmd_cleanup(args):
    with open(args.inventory, encoding="utf-8") as fh:
        inv = json.load(fh)
    policies = inv["policies"]

    hits = parse_hitcount(args.hitcount)

    pattern = args.only or "*"
    excludes = args.exclude or []

    candidates, kept_deny, unknown, excluded = [], [], [], []

    for p in policies:
        key = (p["from_zone"], p["to_zone"], p["name"])
        h = hits.get(key)
        if h is None:
            alt = [v for k, v in hits.items() if k[2] == p["name"]]
            h = alt[0] if len(alt) == 1 else None
        if h is None:
            unknown.append(p)
            continue
        if h["count"] != 0:
            continue
        if not fnmatch.fnmatch(p["name"], pattern):
            continue
        if any(fnmatch.fnmatch(p["name"], ex) for ex in excludes):
            excluded.append(p)
            continue
        action = (h["action"] or p["action"] or "permit").lower()
        if action in ("deny", "reject") and not args.include_deny:
            kept_deny.append(p)
            continue
        candidates.append(p)

    dels, rollback = [], []
    batch = args.batch or "cleanup-hitcount0"
    dels.append(f"# === {batch} : suppression des règles à hit-count 0 ===")
    dels.append("# GARDE-FOUS À VÉRIFIER AVANT COMMIT :")
    dels.append("#  - le compteur hit-count est-il remis à zéro récemment ?")
    dels.append("#    (reboot / clear / bascule cluster) => 0 peut être un faux positif.")
    dels.append("#  - fenêtre d'observation suffisante ? vise >= 90 jours de recul.")
    dels.append("#  - trafic saisonnier (DR, batch trimestriel) non couvert par la fenêtre ?")
    dels.append("#  - charger sous 'configure private', 'commit check', puis "
                "'commit confirmed 10'.")
    dels.append("")
    rollback.append(f"# === rollback {batch} (reconstruit depuis le classement) ===")
    rollback.append("# Champs reconstruits : source/destination/application/action/flags.")
    rollback.append("# Vérifier contre un backup complet pour les options avancées.")
    rollback.append("")

    for p in candidates:
        dels.append(policy_delete_line(p))
        rollback.append(f"# {p['from_zone']}->{p['to_zone']} {p['name']}")
        rollback.extend(policy_set_lines(p))
        rollback.append("")

    out_set = args.output or f"{batch}.set"
    with open(out_set, "w", encoding="utf-8") as fh:
        fh.write("\n".join(dels) + "\n")
    rb = os.path.splitext(out_set)[0] + "-rollback.set"
    with open(rb, "w", encoding="utf-8") as fh:
        fh.write("\n".join(rollback) + "\n")

    print("=" * 64)
    print(f"CLEANUP — batch '{batch}'  (filtre nom: {pattern})")
    print("=" * 64)
    print(f"  règles supprimables (hit-count 0)   : {len(candidates)}")
    for p in candidates:
        print(f"     - {p['from_zone']}->{p['to_zone']} : {p['name']} "
              f"[{p['action']}]")
    if kept_deny:
        print(f"  deny/reject à 0 hit — CONSERVÉS      : {len(kept_deny)} "
              f"(0 hit sur un deny = bon signe ; --include-deny pour forcer)")
        for p in kept_deny:
            print(f"     · {p['from_zone']}->{p['to_zone']} : {p['name']}")
    if excluded:
        print(f"  exclus par --exclude                 : {len(excluded)}")
    if unknown:
        print(f"  sans hit-count correspondant (IGNORÉS): {len(unknown)} "
              f"(conf/hitcount désynchronisés ?)")
        for p in unknown:
            print(f"     ? {p['from_zone']}->{p['to_zone']} : {p['name']}")
    print("-" * 64)
    print(f"  commandes  : {out_set}")
    print(f"  rollback   : {rb}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser():
    ap = argparse.ArgumentParser(
        prog="srxtool",
        description="Analyse de configuration Juniper SRX (inventory / rename / cleanup).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("inventory", help="VLAN->zone->adresses->politiques")
    pi.add_argument("config",
                    help="conf : soit 'show configuration | display xml', "
                         "soit directement 'show configuration' (texte, "
                         "détection automatique du format)")
    pi.add_argument("--json", help="fichier JSON de sortie (classement)")
    pi.add_argument("--xlsx", help="classeur Excel (VLANs / Zones / Policies / Objets)")
    pi.add_argument("--report", help="fichier texte de rapport")
    pi.add_argument("--quiet", action="store_true", help="ne pas imprimer le rapport")
    pi.add_argument("--allow-empty", action="store_true",
                    help="accepter une conf dont rien n'a pu être extrait "
                         "(par défaut : erreur, pour ne pas rendre un rapport vide "
                         "qui ferait croire à une conf saine)")
    pi.set_defaults(func=cmd_inventory)

    pr = sub.add_parser("rename", help="objets nommés en IP -> nom de service")
    pr.add_argument("config", help="conf XML, texte 'show configuration' ou 'display set'")
    pr.add_argument("--suggest", action="store_true",
                    help="phase 1 : écrire le plan CSV")
    pr.add_argument("--from-map", help="phase 2 : CSV rempli -> commandes set/delete")
    pr.add_argument("--dns", action="store_true",
                    help="proposer un nom via reverse DNS (PTR)")
    pr.add_argument("-o", "--output", help="fichier de sortie")
    pr.add_argument("--allow-empty", action="store_true",
                    help="accepter une conf dont rien n'a pu être extrait")
    pr.set_defaults(func=cmd_rename)

    pc = sub.add_parser("cleanup", help="supprimer les règles à hit-count 0")
    pc.add_argument("--inventory", required=True,
                    help="JSON produit par 'inventory --json'")
    pc.add_argument("--hitcount", required=True,
                    help="'show security policies hit-count' en XML ou en texte CLI")
    pc.add_argument("--only", help="nom ou motif glob (ex: 'old-*', 'TEMP-*', '*')")
    pc.add_argument("--exclude", action="append",
                    help="motif à protéger (répétable)")
    pc.add_argument("--include-deny", action="store_true",
                    help="inclure aussi les deny/reject à 0 hit")
    pc.add_argument("--batch", help="nom du lot (nomme les fichiers de sortie)")
    pc.add_argument("-o", "--output", help="fichier de sortie")
    pc.set_defaults(func=cmd_cleanup)

    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    try:
        args.func(args)
    except ConfigFormatError as e:
        print(f"[ERREUR] {e}", file=sys.stderr)
        sys.exit(3)
    except UnsafeNameError as e:
        print(f"[ERREUR] {e}", file=sys.stderr)
        sys.exit(4)


if __name__ == "__main__":
    main()
