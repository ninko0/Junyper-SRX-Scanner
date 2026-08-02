# 04 — Outil 3/3 : Rules — écriture de règles (`internal/rules`)

## Dépend de

Tâche 01 (`internal/config`) et tâche 02 (`internal/inventory`, pour
réutiliser `build_address_index` / l'équivalent Go plutôt que de dupliquer).

## But

C'est le **seul** des 3 outils qui génère des commandes `set`/`delete`
destinées à être chargées sur l'équipement (par l'utilisateur, jamais
automatiquement). Il regroupe ce qui était `rename` et `cleanup` dans
l'ancien `srxtool.py` — deux sous-capacités du même outil "écriture de
règles", pas deux outils séparés.

## Sous-capacité A : rename (objets nommés en IP)

Fonctions de référence :
- `ip_named()` (srxtool.py L811-854) — détecte si un nom d'objet est "en IP"
  (regex `_IP_NAME_RE`, + cas `name == prefix`)
- `app_role()` / `_APP_HINTS` (L?-862) — déduit un rôle applicatif (web, ssh,
  db, ldap, dns, mail, file, ntp, snmp, log) à partir des applications vues
  dans les policies où l'objet est destination
- `ptr_lookup()` (L862-871) — résolution DNS inverse optionnelle (`--dns`).
  **Attention sécurité** : c'est un appel réseau sortant déclenché par le
  contenu de la conf uploadée. En HTTP, ça doit rester une option explicite
  côté utilisateur, avec timeout court et gestion d'échec silencieuse (déjà
  le comportement Python : `except Exception: return None`), jamais bloquant.
- `suggest_name()` (L871-898) — génère un nom proposé (`{zone}-{role}-{octet}`
  ou via PTR)
- Workflow 2 phases à conserver tel quel :
  1. `--suggest` → écrit un CSV plan (`old_name, prefix, zones, refs, apps,
     suggested_new_name, new_name` vide à remplir)
  2. `--from-map` → lit le CSV rempli, génère les commandes de migration
     **sûres** : create le nouvel objet → repointe CHAQUE référence (policies
     src/dst + membres d'address-sets) → delete l'ancien. Jamais un simple
     rename in-place. Voir `set_ref_lines()` (L963-983),
     `addr_create_line()`/`addr_delete_line()` (L948-963).
  3. Génère systématiquement un fichier de rollback (inverse exact des
     opérations).

## Validation des noms — critique côté sécurité

`UnsafeNameError` + `validate_new_name()` + `q()` (srxtool.py L898-948) : le
`new_name` vient d'un CSV rempli à la main par l'utilisateur puis ré-uploadé
côté web. C'est une entrée non fiable qui finit dans des commandes texte
générées. Porter cette validation à l'identique ou plus stricte :
- whitelist de caractères stricte pour un nom d'objet Junos valide
- rejet explicite (erreur claire) si le nom contient des caractères qui
  casseraient la syntaxe `set`/`delete` (espaces non échappés, `;`, guillemets
  non fermés, etc.) — objectif : qu'un nom malveillant dans le CSV ne puisse
  jamais produire une commande de configuration qui ferait autre chose que
  créer/nommer l'objet prévu.

## Sous-capacité B : cleanup (règles à hit-count 0)

Fonctions de référence :
- `parse_hitcount()` (srxtool.py L1473-1544) — parse l'export
  `show security policies hit-count | display xml`, tolérant aux variantes de
  noms de balises
- `cmd_cleanup()` (L1544-1635) — croise l'inventaire avec le hit-count,
  garde-fous à conserver EXACTEMENT :
  - les `deny`/`reject` à 0 hit sont **conservés par défaut** (0 hit sur un
    deny est un bon signe, pas une règle inutile) — flag `--include-deny`
    pour forcer leur inclusion
  - filtrage par motif glob (`--only`) et exclusions (`--exclude`, répétable)
  - policies sans hit-count correspondant → ignorées et listées séparément
    (conf/hitcount potentiellement désynchronisés), jamais supprimées par
    défaut
  - fichier de commandes de suppression **toujours accompagné** d'un
    rollback reconstruit depuis le classement (`policy_set_lines()`,
    `policy_delete_line()`, L983-1009)
  - bannière de garde-fous à conserver dans le fichier généré (fenêtre
    d'observation ≥ 90 jours, hit-count remis à zéro récemment ?, trafic
    saisonnier non couvert ?) — c'est du contenu texte à préserver, pas
    juste une intention

## API du package

```go
package rules

// Rename
func DetectIPNamedObjects(idx AddressIndex) []Candidate
func WriteSuggestCSV(candidates []Candidate, useDNS bool, w io.Writer) error
func ApplyRenameMap(candidates []Candidate, mapping map[string]string) (setCmds, rollback []string, err error)

// Cleanup
func ParseHitcount(r io.Reader) (map[PolicyKey]HitInfo, error)
func Cleanup(policies []config.Policy, hits map[PolicyKey]HitInfo, opts CleanupOptions) CleanupResult
```

## Livrables

- `internal/rules/rename.go`
- `internal/rules/cleanup.go`
- `internal/rules/validate.go` (validation de noms, erreurs sûres)
- `rename-plan.csv` (déjà fourni dans le projet) sert de golden file pour la
  phase `--suggest`
- Tests : cas nominal rename (create→repoint→delete cohérent + rollback exact
  inverse), cas nom invalide dans le CSV (doit être rejeté proprement, pas
  planter ni produire une commande dangereuse), cas cleanup avec deny à 0 hit
  (doit être conservé sauf `--include-deny`), cas policy sans hit-count
  (doit être listée en "ignorée", jamais supprimée).

## Hors périmètre

Pas d'exécution des commandes générées — ce package ne parle jamais au réseau
sauf pour le PTR lookup optionnel du rename, qui reste isolé et non-bloquant.
