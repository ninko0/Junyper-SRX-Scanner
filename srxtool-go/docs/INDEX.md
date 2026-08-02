# Index des tâches — réécriture srxtool en Go

Importe ces fichiers à la racine d'un nouveau dépôt/projet. Chaque fichier est
une tâche indépendante, conçue pour être donnée à une session Claude (ou un
dev) sans avoir besoin de relire tout l'historique — le contexte nécessaire
est rappelé dans chaque MD.

| # | Fichier | Dépend de | Contenu |
|---|---|---|---|
| 00 | `00-overview-et-architecture.md` | — | Vision, stack, repo layout, principes transverses. À lire avant toute autre tâche. |
| 01 | `01-parser-config-junos.md` | 00 | Parsing XML / curly / display-set → modèle commun. **Bloquant.** |
| 02 | `02-tool-inventory.md` | 01 | Outil 1/3 — inventaire VLAN/zone/adresses/policies. |
| 03 | `03-tool-audit.md` | 01 | Outil 2/3 — contrôles de durcissement, findings. |
| 04 | `04-tool-rules.md` | 01, 02 | Outil 3/3 — rename + cleanup, seul générateur de commandes set/delete. |
| 05 | `05-api-http-et-securite-owasp.md` | 02, 03, 04 (stubs OK) | API HTTP, sessions, durcissement OWASP. |
| 06 | `06-frontend-statique.md` | 05 | Frontend statique, sans rendu serveur. |
| 07 | `07-docker-et-conteneurisation.md` | 05, 06 | Dockerfile, compose, exposition localhost-only. |
| 08 | `08-tests-fuzzing-et-ci.md` | 01+ (continu) | Tests, fuzzing, scan sécurité, CI. |
| 09 | `09-migration-et-parite.md` | toutes | Checklist vivante anti-divergence Python→Go. |

## À faire avant de commencer

1. Copier `srxaudit.py`, `srxtool.py`, `app.py` dans `reference/` du nouveau
   projet (lecture seule, jamais exécutés — juste consultés comme spec).
2. Copier les fixtures existantes dans `testdata/fixtures/` : `sample.xml`,
   `sample2.txt`, `sample-show-config.txt`.
3. Copier les sorties de référence dans `testdata/golden/` : `audit.json`,
   `inv.json`, `rename-plan.csv`.
4. Lire `00-overview-et-architecture.md` et valider/ajuster l'hypothèse
   d'architecture (1 binaire / 3 packages internes) avant de lancer la tâche
   01.

## Décisions ouvertes à trancher tôt (marquées dans les MD correspondants)

- Writer XLSX : implémentation maison (zip+XML brut, cohérent avec l'esprit
  stdlib du projet Python d'origine) vs lib externe (`excelize`) — tâche 02.
- Routeur HTTP : stdlib pur vs `chi` — tâche 05.
- Sort de `CONF-GROUPS-INHERITANCE` / `SYS-NO-LO0-FILTER` / `defusedxml`,
  mentionnés dans un résumé de session antérieure mais absents des fichiers
  Python réellement uploadés — tâche 09.
