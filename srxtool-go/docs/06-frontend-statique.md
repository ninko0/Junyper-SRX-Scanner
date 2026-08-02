# 06 — Frontend statique (`web/`)

## Dépend de

Tâche 05 (contrat API stable : routes, formats de réponse JSON).

## But

Remplacer les pages générées côté serveur (`render_template_string`,
`PAGE_HEAD`/`UPLOAD_FORM`/`RESULTS_TMPL` de l'ancien `app.py`) par un frontend
statique qui consomme l'API JSON. Élimine la classe de risque SSTI et sépare
clairement présentation et traitement de données.

## Pages / vues nécessaires (parité avec l'ancien `app.py`)

1. **Accueil / upload** — formulaire de dépôt de fichier conf (multipart),
   sélection du seuil de sévérité minimum pour l'audit, bouton "Analyser".
   Affiche un message d'erreur si `/api/analyze` renvoie une erreur (format
   non reconnu, fichier trop gros...).
2. **Résultats** — affichage synthétique des comptages par sévérité (audit) et
   des comptages zones/VLANs/policies/objets (inventory), badges colorés par
   sévérité identiques à la palette XLSX (cohérence visuelle), avertissements
   éventuels (`warnings` du modèle, ex. `groups` non résolus), liens de
   téléchargement vers les fichiers de sortie (txt/json/xlsx/fix).
3. **Rules — rename** — upload conf → téléchargement du CSV plan ; puis
   upload du CSV rempli → téléchargement des commandes + rollback.
4. **Rules — cleanup** — upload JSON d'inventaire + export hit-count →
   téléchargement des commandes + rollback, avec affichage clair de la
   séparation candidats supprimables / deny conservés / exclus / ignorés
   (même structure d'information que le rapport console `cmd_cleanup()`).

## Choix technique

Vanilla HTML/CSS/JS, sans framework serveur de rendu. Un framework client
léger (ex. Alpine.js, ou juste JS natif avec `fetch`) est acceptable si ça
simplifie l'état de l'UI, mais éviter d'introduire un gros framework (React
etc.) pour ce qui reste un outil interne simple — garder le principe "moins de
dépendances" cohérent avec le reste du projet.

## Contraintes sécurité côté frontend

- **Pas de JS inline, pas de `eval`** — cohérent avec le `Content-Security-
  Policy` strict défini en tâche 05 (pas de `unsafe-inline`).
- **Échappement systématique** de tout ce qui vient de l'API avant insertion
  dans le DOM (noms de fichiers, messages d'erreur, contenu de findings) —
  utiliser `textContent`/`innerText` plutôt que `innerHTML` partout où c'est
  de la donnée, jamais de concaténation de chaînes HTML avec de la donnée
  serveur.
- **Validation côté client** en plus (pas à la place) de la validation
  serveur : taille de fichier, extension attendue avant upload — améliore
  l'UX, ne remplace jamais les contrôles serveur de la tâche 05.
- **Liens de téléchargement** : utiliser les URLs telles que renvoyées par
  l'API (avec le `sid` généré serveur), ne jamais construire un chemin de
  téléchargement à partir d'une saisie utilisateur libre côté client.

## Conservation du contenu utile de l'ancien template

- Le bandeau d'avertissement (`.warn`) affichant `audit_warnings` /
  `source_format` détecté — utile pour que l'utilisateur sache si sa conf a
  été lue en XML/curly/set et s'il y a des `groups` non résolus.
- Les badges de sévérité colorés (`.b-crit`, `.b-high`, `.b-med`, `.b-low`,
  `.b-info`) — mêmes couleurs que la palette XLSX pour la cohérence visuelle
  entre l'UI et les exports.

## Livrables

- `web/index.html`, `web/results.html` (ou SPA à routes JS, au choix)
- `web/style.css`
- `web/app.js` (ou fichiers séparés par page)
- Le binaire Go sert ces fichiers statiques (via `embed` de la stdlib Go pour
  les inclure dans le binaire final — évite d'avoir à gérer un volume séparé
  pour les assets statiques en prod)

## Conformité AGPL — lien "Source" obligatoire

Le projet est sous AGPL-3.0-or-later. La section 13 impose que les
utilisateurs qui interagissent avec le service **par le réseau** puissent
récupérer le code source de la version qui tourne. Concrètement, à prévoir
dans le frontend :

- Un lien **"Source"** visible dans le pied de page de chaque vue, pointant
  vers le dépôt (et, si le déploiement fait tourner une version modifiée, vers
  l'archive du code réellement déployé).
- Afficher la version/le commit du binaire en cours (à exposer par l'API,
  ex. `GET /healthz` ou un `GET /api/version`) pour que le lien corresponde
  bien à la version servie.

Ce n'est pas un détail cosmétique : c'est la condition qui rend le
déploiement conforme dès qu'il n'est plus strictement mono-utilisateur en
localhost.

## Hors périmètre

Pas de build step complexe (webpack/vite) requis si on reste en vanilla JS —
à réévaluer seulement si la complexité de l'UI le justifie vraiment.
