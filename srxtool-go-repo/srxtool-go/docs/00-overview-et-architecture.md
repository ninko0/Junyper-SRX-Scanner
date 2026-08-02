# 00 — Vue d'ensemble & architecture (srxtool v2, Go)

## Contexte

Réécriture de `srxaudit.py` + `srxtool.py` (Python, stdlib only) en Go, avec
une vraie couche web (au lieu du Flask + `render_template_string` de l'ancien
`app.py`), conteneurisée, et durcie selon OWASP. Déploiement cible : **local,
localhost uniquement, pas d'authentification pour l'instant** — la seule
barrière de sécurité est le réseau (le service n'écoute que sur
`127.0.0.1`/l'interface Docker interne).

But n°1 de la réécriture : **ne pas diverger** du comportement fonctionnel
existant (mêmes contrôles d'audit, mêmes codes, mêmes sévérités, même modèle
d'inventaire, même logique de génération de commandes `set`/`delete`). Le
fichier `09-migration-et-parite.md` sert de checklist de non-régression.

## Hypothèse d'architecture (à valider)

**Un seul binaire Go, un seul conteneur**, avec 3 domaines métier découplés en
packages internes distincts (pas 3 services séparés). Raison : c'est un outil
local mono-utilisateur pour l'instant, la complexité opérationnelle de 3
conteneurs n'apporte rien tant qu'il n'y a pas de besoin de scaling/déploiement
indépendant. Les packages sont écrits de façon à pouvoir être extraits en
services séparés plus tard sans réécriture (pas de dépendance croisée cachée,
communication via interfaces claires).

Si tu préfères réellement 3 conteneurs dès le départ, dis-le — ça change
uniquement les tâches 05 et 07 (routing HTTP et Dockerfile/compose), pas les
packages métier eux-mêmes.

## Les 3 domaines (demande explicite de re-segmentation)

1. **Inventory** — classement VLAN → zone → adresses → politiques. Lecture
   seule, aucune génération de commande.
2. **Audit** — contrôles de durcissement, findings classés par sévérité.
   Lecture seule, génère des *suggestions* de correctifs mais ne les exécute
   jamais.
3. **Rules** (ex `rename` + `cleanup` de l'ancien `srxtool.py`) — la seule
   partie qui **génère des commandes `set`/`delete`** à charger manuellement
   sur l'équipement. Toujours accompagné d'un rollback. Jamais d'exécution
   automatique — c'est un générateur de texte, pas un outil de déploiement.

## Stack technique

- **Langage** : Go (1.22+)
- **HTTP** : stdlib `net/http` + `chi` (routeur léger, pas de magie, bon
  support middleware) — à confirmer dans la tâche 05, stdlib pur reste une
  option si tu veux zéro dépendance de routing.
- **Frontend** : HTML/CSS/JS statique, pas de framework serveur de templates
  (élimine toute la classe de risques SSTI qu'avait `render_template_string`).
- **Conteneur** : multi-stage Dockerfile, image finale `distroless` ou
  `scratch`, utilisateur non-root, filesystem en lecture seule sauf le
  répertoire de sessions.
- **Pas de base de données** : les résultats d'analyse sont stockés comme
  fichiers de session sur disque (comme l'ancien `app.py`), avec TTL de
  nettoyage. Une session = un répertoire nommé par un identifiant aléatoire
  non prévisible (UUID), jamais dérivé d'une entrée utilisateur.

## Repo layout cible

```
srxtool-go/
  README.md
  go.mod
  cmd/
    server/
      main.go              # point d'entrée unique
  internal/
    config/                # tâche 01 — parsing Junos (curly/set/xml)
    xlsx/                  # tâche 01 (partagé) — writer XLSX minimal
    inventory/             # tâche 02
    audit/                 # tâche 03
    rules/                 # tâche 04 (rename + cleanup)
    api/                   # tâche 05 — handlers HTTP, middleware, routing
    session/               # tâche 05 — gestion des sessions/fichiers
  web/                      # tâche 06 — frontend statique
  testdata/
    fixtures/               # sample.xml, sample2.txt, sample-show-config.txt
    golden/                 # sorties attendues (JSON/txt figés) — tâche 09
  Dockerfile                # tâche 07
  docker-compose.yml         # tâche 07
  .github/workflows/ci.yml  # tâche 08
```

## Principes transverses (valables pour TOUTES les tâches)

- **Aucune commande n'est jamais poussée sur un équipement.** Chaque service
  ne fait que lire une conf et écrire des fichiers de sortie (JSON/texte/XLSX/
  correctifs) que l'utilisateur relit et charge lui-même.
- **Toute entrée utilisateur est non fiable** : nom de fichier, contenu de
  conf uploadée, contenu du CSV de rename rempli à la main (peut contenir des
  noms d'objets malveillants — cf `UnsafeNameError`/`validate_new_name` côté
  Python, à porter dans la tâche 04).
- **Pas de traversée de chemin** : les identifiants de session sont validés
  par motif strict (regex hexadécimal), jamais utilisés bruts dans un
  `filepath.Join` sans vérification `filepath.Clean` + préfixe du répertoire
  de base après résolution (`filepath.EvalSymlinks` ou équivalent).
- **Pas de désérialisation dangereuse**, pas de `exec.Command` construit à
  partir d'entrée utilisateur (les "commandes set/delete" générées sont du
  texte affiché/téléchargé, jamais exécuté par le service lui-même).
- **Erreurs** : messages d'erreur utilisateur génériques, jamais de stack
  trace ni de chemin absolu du serveur renvoyé au client. Logs détaillés côté
  serveur uniquement (stdout structuré, capturé par Docker).

## Licence

AGPL-3.0-or-later. Conséquence concrète sur l'implémentation (pas seulement
sur le fichier LICENSE) : le service doit exposer sa version et un lien vers
son code source dans l'UI — voir la tâche 06. Prévoir aussi un
`GET /api/version` côté API (tâche 05) renvoyant version + commit.

## Ordre de réalisation recommandé

1. Tâche 01 (parser) — bloquant pour tout le reste.
2. Tâches 02, 03, 04 (inventory / audit / rules) — indépendantes entre elles
   une fois 01 fait, réalisables dans n'importe quel ordre ou en parallèle.
3. Tâche 05 (API + sécurité) — dépend de 02/03/04 au moins partiellement
   présentes (peut démarrer avec des stubs).
4. Tâche 06 (frontend) — dépend de 05 (contrat API stable).
5. Tâche 07 (Docker) — peut être préparée en parallèle, finalisée à la fin.
6. Tâche 08 (tests/CI) — en continu, mais la mise en place initiale peut
   suivre juste après la tâche 01.
7. Tâche 09 (parité) — checklist vivante, à cocher au fur et à mesure.

## Fichiers source Python de référence

Toutes les tâches ci-dessous référencent des fonctions précises de
`srxaudit.py` et `srxtool.py` (version "finale", celle avec `ConfigFormatError`,
`parse_set_text`, `UnsafeNameError`, export XLSX intégré). Ces deux fichiers
doivent être ajoutés au nouveau projet sous `reference/srxaudit.py` et
`reference/srxtool.py` (lecture seule, jamais exécutés, juste consultés comme
spec de comportement) — ainsi que `app.py` sous `reference/app.py` pour la
logique de session/auth/téléchargement de l'ancienne version Flask.
