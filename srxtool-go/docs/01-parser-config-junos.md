# 01 — Package `internal/config` : parsing de configuration Junos

## Dépend de

Rien (première tâche). **Bloque toutes les autres tâches métier.**

## But

Porter en Go le parsing multi-format de `srxtool.py`, qui transforme une conf
Junos (peu importe le format fourni) en un modèle de données unifié
réutilisé ensuite par inventory/audit/rules.

## Formats d'entrée à supporter (auto-détection, comme en Python)

1. **XML** — `show configuration | display xml` → fonctions de référence
   `parse_config_xml()` (srxtool.py L412-529) et `parse_xml()` (srxaudit.py
   L164-226). Utiliser `encoding/xml` de la stdlib Go.
2. **Texte à accolades** — `show configuration` brut copié-collé du CLI Junos
   → fonctions de référence `parse_curly_text()` (srxtool.py L113-186),
   `parse_config_text()` (srxtool.py L562-680), `parse_text()` (srxaudit.py
   L226-313). Attention aux idiomes Junos spécifiques :
   - `family inet { address x/y; }` → adresses d'unité d'interface
   - conteneurs "liste de noms nus" (`interfaces { ge-0/0/0; ge-0/0/1; }`,
     VLANs) via `cbare_names()`
   - blocs `from-zone X to-zone Y { policy NOM { ... } }`
   - conteneurs "flag-set" qui deviennent une liste de tokens répétés
     (`host-inbound-traffic { system-services { ping; ssh; } }`)
   - `address-book { global { ... } }` vs `address-book` attaché directement
     à une `security-zone`
   - syntaxe `clé [ v1 v2 v3 ];` (liste inline) → voir `_split_tokens()`
     (srxtool.py L90-105, gère le split façon shell + les crochets `[ ]`)
3. **`display set`** — `show configuration | display set` → fonction de
   référence `parse_set_text()` (srxtool.py L186-257). C'est le format le
   plus récent ajouté côté Python, bien vérifier qu'il est couvert.

Auto-détection : voir `looks_like_xml()` (L257), `looks_like_set_format()`
(L261), `parse_text_auto()` (L278-288) — porter la même heuristique d'ordre
de détection.

## Modèle de données cible (Go structs)

Reproduire fidèlement la structure produite par `_finalize_model()`
(srxtool.py L680-709) et le dict `m` de `srxaudit.parse()` (L313-341) :

```go
type Model struct {
    Units        map[string]Unit
    VLANs        map[string]VLAN
    Zones        map[string]Zone
    GlobalBooks  map[string]AddressBook
    Policies     []Policy
    Warnings     []string   // ex: groups/apply-groups non résolus
    SourceFormat string     // "xml" | "curly" | "set"
}
```

Champs à reprendre exactement (mêmes noms de concept, adaptés en Go
idiomatique) : `Unit{Interface, Unit, Inet []string, VLANMembers []string}`,
`VLAN{VlanID, L3Interface, Members, Zone, L3Addresses}`, `Zone{Interfaces,
LegacyBook, Policies, SystemServices, Protocols, Screen, Public bool}`,
`Policy{FromZone, ToZone, Name, Source, Destination, Application, Action,
Flags}`.

## Erreurs à porter

- `ConfigFormatError` (srxtool.py L105) — équivalent Go : type d'erreur
  sentinelle exportée (`config.ErrFormat` ou `*config.FormatError`)
  distinguable via `errors.As`, avec un message explicite indiquant le format
  attendu. Levée quand aucun des 3 parseurs ne reconnaît l'entrée, ou quand le
  résultat est structurellement vide (`assert_model_not_empty()`, L709-731).
- Pas de panique sur entrée malformée : toute conf invalide doit retourner une
  erreur Go normale, jamais un `panic`. Fuzzer cette propriété dans la tâche
  08.

## Sécurité XML spécifique

Go `encoding/xml` n'a pas la classe de vulnérabilités XXE de la même manière
que les parseurs XML C-based, mais reste rigoureux :
- Limiter la taille du fichier d'entrée *avant* parsing (voir tâche 05 pour la
  limite au niveau HTTP, mais le package `config` doit aussi accepter une
  limite en paramètre pour être testable indépendamment du serveur HTTP).
- Pas de résolution d'entités externes (comportement par défaut de
  `encoding/xml`, à vérifier et documenter en commentaire).

## Fonctions helper à porter

`ln()`, `kids()`, `kid()`, `txt()`, `find_config_root()` (récursion pour
localiser `<configuration>` où qu'il soit dans l'arbre, y compris sous
`rpc-reply`) — équivalents Go opérant sur `xml.Token`/structs générés, ou sur
l'AST texte pour les 2 autres formats (`cchildren`, `cchild`, `cleaf`,
`cvalues`, `chas`, `cbare_names`, `cbare_value` — srxtool.py L288-376).

## Livrables

- `internal/config/parse.go` (dispatch + détection de format)
- `internal/config/xml.go`, `curly.go`, `set.go` (un parseur par format)
- `internal/config/model.go` (structs)
- `internal/config/errors.go`
- Tests unitaires avec les 3 fixtures déjà disponibles : `sample.xml`,
  `sample2.txt` (curly), `sample-show-config.txt` (curly) — à copier dans
  `testdata/fixtures/`. Ajouter un fixture `display set` équivalent (à générer
  à partir d'un des deux existants, ou fourni séparément).
- Test de non-régression : parser les 3 fixtures et vérifier que le modèle
  obtenu contient les mêmes zones/VLANs/policies que ce que produit le Python
  actuel sur les mêmes fichiers (comparaison manuelle ou golden JSON — voir
  tâche 09).

## Hors périmètre de cette tâche

Pas de logique métier (checks d'audit, inventaire, génération de commandes) —
uniquement le parsing vers le modèle commun.
