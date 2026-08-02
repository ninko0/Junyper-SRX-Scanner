# 02 — Outil 1/3 : Inventory (`internal/inventory`)

## Dépend de

Tâche 01 (`internal/config`) doit être terminée ou au moins avoir un modèle
stable pour ce fixture.

## But

Reproduire `srxtool.py inventory` : classement VLAN → zone → adresses →
politiques, en lecture seule (aucune commande générée).

## Fonctions de référence (Python)

- `build_inventory_model()` (srxtool.py L1227-1257) — assemble le modèle +
  `zone_objects` + `address_objects` à partir de `parse_config()`
- `build_address_index()` (srxtool.py L745-811) — construit l'index des
  objets d'adresse (globaux + par zone) et leurs usages (référencés dans
  quelles policies / address-sets)
- `build_inventory_report_text()` (srxtool.py L1257-1305) — rapport texte
  lisible (zones, VLANs orphelins sans zone L3, compte d'objets/politiques)
- `export_inventory_xlsx()` (srxtool.py L1156-1227) — classeur Excel
  (VLANs / Zones / Policies / Objets d'adresse), voir tâche sur le writer XLSX
  ci-dessous
- `cmd_inventory()` (srxtool.py L1305-1357) — orchestration CLI, à traduire en
  fonction de service pure (pas de dépendance à `argparse`/stdout)

## Ce que le package doit exposer

```go
package inventory

type Result struct {
    Model         config.Model
    ZoneObjects   map[string][]string   // zone -> noms d'objets d'adresse
    AddressObjects []AddressObject
}

func Build(model config.Model) Result
func (r Result) ReportText() string
func (r Result) JSON() ([]byte, error)
func (r Result) ExportXLSX(w io.Writer) error
```

Signature volontairement pure (pas d'I/O disque directe pour le rapport/JSON,
pour rester testable et réutilisable par la couche HTTP de la tâche 05). Seul
`ExportXLSX` prend un `io.Writer` (le contenu XLSX est binaire, un writer est
l'abstraction naturelle — ça permet de streamer directement vers la réponse
HTTP sans fichier temporaire si souhaité).

## Point d'attention : VLANs orphelins

Le Python signale explicitement les VLANs sans zone L3 rattachée (pas de
`l3-interface` résolvable vers une zone) — c'est un warning utile pour
détecter les erreurs de conf, à garder identique dans le rapport Go.

## Writer XLSX partagé

L'ancien code duplique un générateur XLSX minimal (`zipfile` + XML brut) entre
`srxaudit.py` et `srxtool.py`, avec une palette de couleurs par sévérité
(`FILLS` dict, srxaudit.py L633-654 / srxtool.py L1009-1030 — identiques dans
les deux fichiers, exactement le genre de duplication que la réécriture doit
éliminer). Créer un package `internal/xlsx` unique et partagé (utilisable
aussi par la tâche 03), avec :
- Palette de couleurs par sévérité identique (CRITICAL rouge foncé, HIGH
  rouge/orange, MEDIUM jaune, LOW vert clair, INFO gris, + ORPHAN/OK pour
  l'inventaire)
- API simple : `xlsx.Writer` avec `AddSheet(name string, headers []string,
  rows [][]Cell)` où `Cell` porte une valeur + un style optionnel
- Utiliser soit une implémentation manuelle façon Python (zip + XML minimal,
  zéro dépendance externe, cohérent avec l'esprit stdlib-only d'origine), soit
  une lib Go mature (`github.com/xuri/excelize` ou `github.com/tealeg/xlsx`)
  si tu préfères ne pas réinventer le format OOXML à la main. **Décision à
  prendre au moment de cette tâche** — les deux sont valables, la lib externe
  réduit le risque de bug de génération de fichier corrompu, le code maison
  réduit la surface de dépendances tierces (cohérent avec le principe
  "moins de supply-chain" discuté pour le choix de Go).

## Livrables

- `internal/inventory/inventory.go`
- `internal/xlsx/xlsx.go` (partagé, réutilisé en tâche 03)
- Tests unitaires sur les 3 fixtures existantes, comparant au minimum : nombre
  de zones, nombre de VLANs, nombre de policies, présence/absence des VLANs
  orphelins attendus (`VLAN99` dans `sample2.txt` et `sample-show-config.txt`
  n'a pas de `l3-interface` → doit apparaître en orphelin).
- `inv.json` (déjà fourni dans le projet) peut servir de golden file de
  référence pour la structure JSON attendue sur `sample2.txt`.

## Hors périmètre

Pas de détection d'objets nommés en IP (`ip_named`/`suggest_name`) — ça
appartient à la tâche 04 (rules/rename), même si ça réutilise l'index
d'adresses construit ici. Le package `rules` importera `inventory` pour ça
plutôt que de dupliquer `build_address_index`.
