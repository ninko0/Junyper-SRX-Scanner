# 03 — Outil 2/3 : Audit (`internal/audit`)

## Dépend de

Tâche 01 (`internal/config`). Réutilise `internal/xlsx` créé en tâche 02 (si
02 n'est pas encore faite, créer `internal/xlsx` en avance de phase minimal ou
dupliquer temporairement — mais le but final est un seul writer XLSX partagé).

## But

Reproduire `srxaudit.py` : catalogue de contrôles de durcissement fixes,
findings classés par sévérité, rapport + JSON + XLSX + fichier de correctifs
`set`/`delete` en texte (jamais exécutés).

## Modèle `Finding`

Reproduire `Finding` (srxaudit.py L130-164) :

```go
type Severity string

const (
    Critical Severity = "CRITICAL"
    High     Severity = "HIGH"
    Medium   Severity = "MEDIUM"
    Low      Severity = "LOW"
    Info     Severity = "INFO"
)

var severityRank = map[Severity]int{
    Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4,
}

type Finding struct {
    Severity Severity
    Check    string   // ex "POL-ANY-ANY"
    Title    string
    Where    string
    Reco     string
    Ref      string
    Fix      []string // commandes set/delete suggérées, jamais exécutées
}
```

## Catalogue de contrôles à porter EXACTEMENT (mêmes codes, mêmes sévérités)

C'est le cœur de la parité fonctionnelle — voir la checklist détaillée dans
`09-migration-et-parite.md`, mais liste de référence complète des codes
actuels (vérifiée dans le code source, pas seulement documentée) :

**Policies** (`check_policies()`, srxaudit.py L341-429) :
`POL-ANY-ANY`, `POL-APP-ANY`, `POL-BROAD-ADDR`, `POL-INBOUND-ANY`,
`POL-OBSOLETE-APP`, `POL-NOLOG-PERMIT`, `POL-NOLOG-DENY`

**Zones** (`check_zones()`, srxaudit.py L429-504) :
`ZONE-NO-SCREEN`, `ZONE-NO-SCREEN-INT`, `ZONE-SCREEN-MISSING`,
`ZONE-HIB-ALL`, `ZONE-HIB-MGMT-EXT`, `ZONE-HIB-PROTO-ALL`

**Système** (`check_system()`, srxaudit.py L504-633) :
`SYS-TELNET`, `SYS-FTP`, `SYS-FINGER`, `SYS-RLOGIN`, `SYS-RSH`,
`SYS-TFTP-SERVER`, `SYS-XNM-CLEAR-TEXT` (ces 7 générés dynamiquement via
`flag_service()`, ne pas les oublier car un simple `grep` sur le code ne les
trouve pas comme littéraux), `SYS-SSH-ROOT`, `SYS-SSH-V1`,
`SYS-WEBMGMT-HTTP`, `SYS-NO-SYSLOG`, `SYS-NO-NTP`, `SYS-NO-BANNER`

**SNMP** (fin de `check_system()`) :
`SNMP-DEFAULT-COMM`, `SNMP-RW`, `SNMP-NO-V3`

Pour chaque contrôle : reprendre exactement le texte de `reco` et `ref` (les
références NIST/CIS/charte interne/NIS2 sont du contenu métier à préserver
mot pour mot, pas juste la logique).

Attention aux listes de constantes utilisées par les contrôles :
`OBSOLETE_APPS` (srxaudit.py, dict protocole → libellé humain),
`EXTERNAL_ZONE_HINT` (noms de zones considérées externes par heuristique :
untrust/internet/wan/outside/external/inet), `MGMT_SERVICES` (services de
gestion à ne jamais exposer côté externe).

## Fonctions d'orchestration à porter

- `render()` / `build_report_text()` / `build_findings_json()` /
  `build_fix_text()` / `count_by_severity()` (srxaudit.py L780-895) — séparer
  proprement génération de contenu (pure, testable) et écriture disque
  (laissée à la couche appelante, HTTP ou CLI).
- Tri des findings : par rang de sévérité puis code puis emplacement
  (`findings.sort(...)`, reproduire l'ordre exact pour des sorties
  déterministes et diffables).
- Filtrage par `--min-severity` (seuil de sévérité minimum affiché).

## API du package

```go
package audit

func Run(model config.Model) []Finding
func ReportText(findings []Finding) string
func FindingsJSON(findings []Finding) ([]byte, error)
func FixText(findings []Finding) string
func ExportXLSX(findings []Finding, w io.Writer) error
func FilterMinSeverity(findings []Finding, min Severity) []Finding
```

## Livrables

- `internal/audit/checks.go` (le catalogue de contrôles)
- `internal/audit/report.go` (rendu texte/JSON/XLSX/fix)
- `audit.json` (déjà fourni dans le projet) sert de **golden file** direct :
  faire tourner l'implémentation Go sur la conf qui a produit ce JSON
  (reconstituer ou identifier la conf source correspondante — probablement
  proche de `sample-show-config.txt`, à vérifier) et comparer champ par champ.
- Tests unitaires par contrôle (au moins un cas qui déclenche chaque code, un
  cas qui ne le déclenche pas) plutôt qu'un seul test bout-en-bout — plus
  facile à maintenir et à faire échouer précisément en cas de régression.

## Hors périmètre

Pas de génération de commandes de correction *automatique* au sens "prêtes à
charger sans relecture" — le `Fix` reste, comme en Python, du texte suggéré
(souvent commenté avec `#` quand une valeur humaine est requise). La
génération de commandes fiables et exécutables en masse, c'est le rôle de
l'outil 3 (rules), pas de l'audit.
