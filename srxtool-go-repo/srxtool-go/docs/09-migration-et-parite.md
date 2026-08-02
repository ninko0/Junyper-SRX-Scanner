# 09 — Checklist de parité fonctionnelle (Python → Go)

## But

Document vivant, à cocher au fur et à mesure. Objectif explicite de la
réécriture : **éviter les divergences** avec le comportement Python actuel.
Toute divergence volontaire doit être notée ici avec sa justification, pas
silencieusement introduite.

## Comment l'utiliser

Après chaque tâche (01-04 principalement), revenir ici et cocher les lignes
concernées en confirmant que le comportement Go a été comparé au Python sur
les fixtures disponibles (`sample.xml`, `sample2.txt`,
`sample-show-config.txt`) et, quand c'est pertinent, aux fichiers de sortie
déjà générés fournis dans le projet (`audit.json`, `inv.json`,
`rename-plan.csv`).

## Parsing (tâche 01)

- [ ] Détection de format identique sur les 3 fixtures (xml / curly / set)
- [ ] `find_config_root` : localisation de `<configuration>` sous `rpc-reply`
      ou variantes, testée
- [ ] Idiome `family inet { address }` correctement extrait
- [ ] Idiome liste inline `clé [ v1 v2 v3 ];` correctement splitté
- [ ] `host-inbound-traffic { system-services { ... } }` → liste plate
      identique
- [ ] `address-book { global { ... } }` vs address-book de zone : les deux
      cas produisent le même modèle qu'en Python
- [ ] VLAN sans `l3-interface` → `zone: null`, `l3_addresses: []` (cf
      `VLAN99` dans les fixtures)
- [ ] `ConfigFormatError` levée dans les mêmes conditions qu'en Python
      (aucun des 3 formats reconnu, ou modèle vide)
- [ ] `warnings` (ex. groups non résolus, si repris — cf note dans le MD 00
      sur `CONF-GROUPS-INHERITANCE` absent des fichiers actuels, à trancher)

## Inventory (tâche 02)

- [ ] Nombre de zones/VLANs/policies identique sur les 3 fixtures
- [ ] VLANs orphelins détectés identiquement
- [ ] `address_objects` : mêmes objets, mêmes `references` count
      (comparaison directe possible avec `inv.json` fourni sur `sample2.txt`)
- [ ] Rapport texte : structure équivalente (zones triées, VLANs listés avec
      subnet/ports, compteurs de policies from/to)

## Audit (tâche 03) — vérifier CHAQUE code un par un

- [ ] `POL-ANY-ANY` (CRITICAL si zone externe, HIGH sinon)
- [ ] `POL-APP-ANY`
- [ ] `POL-BROAD-ADDR`
- [ ] `POL-INBOUND-ANY`
- [ ] `POL-OBSOLETE-APP` (vérifier la table `OBSOLETE_APPS` complète : telnet,
      ftp, tftp, rlogin, rsh, http, snmp, snmp-agentx, ldap)
- [ ] `POL-NOLOG-PERMIT`
- [ ] `POL-NOLOG-DENY` (déclenché seulement si action deny/reject ET
      `session-init` absent des logs)
- [ ] `ZONE-NO-SCREEN` (HIGH, zone externe)
- [ ] `ZONE-NO-SCREEN-INT` (LOW, zone interne)
- [ ] `ZONE-SCREEN-MISSING` (screen référencé mais non défini)
- [ ] `ZONE-HIB-ALL` (CRITICAL externe / HIGH interne)
- [ ] `ZONE-HIB-MGMT-EXT`
- [ ] `ZONE-HIB-PROTO-ALL`
- [ ] `SYS-TELNET`, `SYS-FTP`, `SYS-FINGER`, `SYS-RLOGIN`, `SYS-RSH`,
      `SYS-TFTP-SERVER`, `SYS-XNM-CLEAR-TEXT` — les 7 générés dynamiquement,
      à tester individuellement (facile à oublier un des 7)
- [ ] `SYS-SSH-ROOT`
- [ ] `SYS-SSH-V1`
- [ ] `SYS-WEBMGMT-HTTP`
- [ ] `SYS-NO-SYSLOG`
- [ ] `SYS-NO-NTP`
- [ ] `SYS-NO-BANNER`
- [ ] `SNMP-DEFAULT-COMM` (communautés `public`/`private`)
- [ ] `SNMP-RW`
- [ ] `SNMP-NO-V3`
- [ ] Ordre de tri des findings identique (sévérité, puis code, puis
      emplacement)
- [ ] Comparaison directe champ-à-champ avec `audit.json` fourni (identifier
      d'abord quelle conf source le reproduit exactement, probablement une
      variante proche de `sample-show-config.txt`)
- [ ] Textes de `recommendation`/`reference` repris mot pour mot (pas
      seulement la logique de déclenchement)

## Rules — rename (tâche 04)

- [ ] `ip_named` : mêmes cas détectés (nom == prefix, regex avec préfixe
      optionnel type `h-`/`host_`/`net_`, masque optionnel)
- [ ] `app_role` : mêmes rôles déduits pour les mêmes applications (web, ssh,
      rdp, db, ldap, dns, mail, file, ntp, snmp, log)
- [ ] `suggest_name` format identique (`{zone}-{role}-{octet}` ou
      `{zone}-host-{octet}` si pas de rôle déduit)
- [ ] CSV `--suggest` : mêmes colonnes, même ordre — comparable directement à
      `rename-plan.csv` fourni
- [ ] Workflow `--from-map` : create → repoint TOUTES les références → delete,
      jamais un rename in-place
- [ ] Rollback : inverse exact des opérations
- [ ] `UnsafeNameError` : mêmes noms rejetés (caractères dangereux pour la
      syntaxe `set`/`delete`)

## Rules — cleanup (tâche 04)

- [ ] `parse_hitcount` : tolérance aux variantes de noms de balises
      (`from-zone`, `to-zone`, `policy-name`, `count`, `policy-action`/
      `action`)
- [ ] Deny/reject à 0 hit conservés par défaut, `--include-deny` pour forcer
- [ ] Filtrage `--only` (glob) et `--exclude` (répétable) identiques
- [ ] Policies sans hit-count correspondant → listées en "ignorées", jamais
      supprimées
- [ ] Bannière de garde-fous présente dans le fichier de commandes généré
      (texte, pas juste la logique)
- [ ] Rollback généré systématiquement

## Divergences volontaires (à documenter ici au fur et à mesure)

| Domaine | Comportement Python | Comportement Go | Justification |
|---|---|---|---|
| _(exemple)_ Sessions | id tronqué à 12 hex chars | UUID v4 complet | pas d'auth par-dessus, l'id de session doit rester non-devinable |
| | | | |

## Contrôles Python mentionnés en résumé de session mais absents des fichiers uploadés

À trancher avec l'utilisateur avant ou pendant la réécriture (ne pas les
inventer sans confirmation) :
- `CONF-GROUPS-INHERITANCE`
- `SYS-NO-LO0-FILTER`
- Durcissement `defusedxml` côté parsing XML (en Go, `encoding/xml` n'a pas le
  même profil de risque XXE que `xml.etree`/`lxml` côté Python, donc ce point
  précis est probablement sans objet — à confirmer en tâche 01 et noter ici la
  conclusion)
