# 05 — API HTTP, sessions & durcissement OWASP (`internal/api`, `internal/session`)

## Dépend de

Au moins des stubs des packages `inventory`, `audit`, `rules` (tâches 02/03/04)
— peut démarrer avec des interfaces définies avant que l'implémentation
complète de ces packages soit finie.

## But

Exposer les 3 outils via HTTP, sans authentification (protection = réseau
uniquement, localhost/interne Docker), mais durci selon OWASP ASVS/Top10 dans
tout ce qui ne dépend pas de l'auth.

## Routes cibles

```
POST /api/analyze                # upload une conf → lance les 3 analyses, crée une session
GET  /api/sessions/{sid}/inventory/report.txt
GET  /api/sessions/{sid}/inventory/report.json
GET  /api/sessions/{sid}/inventory/report.xlsx
GET  /api/sessions/{sid}/audit/report.txt
GET  /api/sessions/{sid}/audit/report.json
GET  /api/sessions/{sid}/audit/report.xlsx
GET  /api/sessions/{sid}/audit/fix.set
POST /api/rules/rename/suggest    # upload conf → CSV plan
POST /api/rules/rename/apply      # upload CSV rempli + conf → commandes + rollback
POST /api/rules/cleanup           # upload inventory JSON + hitcount XML → commandes + rollback
GET  /healthz
```

Reste proche du contrat de l'ancien `app.py` (upload → session → téléchargement
par item whitelisté) mais en API JSON pure, pas de HTML généré côté serveur.

## Gestion des sessions (`internal/session`)

Porter la logique de `app.py` L102-146 mais en durcissant :
- Identifiant de session : UUID v4 uniquement (pas de `[:12]` tronqué comme en
  Python — garder l'entropie complète, un identifiant de session est un
  secret de capacité vu qu'il n'y a pas d'auth par-dessus).
- Répertoire de session sous un `BaseDir` dédié, jamais dans `/tmp` partagé du
  système hôte si le service tourne en dehors de Docker — dans le conteneur,
  un volume dédié (voir tâche 07).
- **Validation stricte à la lecture** : `sid` matché contre une regex
  hexadécimale de longueur fixe, `fname` contre une whitelist explicite de
  noms de fichiers possibles (jamais un nom arbitraire pris depuis l'URL) —
  c'est exactement la faille corrigée dans l'historique Python
  (`basename("..")` qui vaut `".."`, contournable) : en Go, ne pas se fier à
  `filepath.Base` seul non plus, faire la même whitelist + vérification que le
  chemin résolu (`filepath.EvalSymlinks` + comparaison de préfixe) reste sous
  `BaseDir`.
- TTL de nettoyage best-effort (goroutine périodique ou nettoyage lazy à
  chaque requête, au choix — documenter le choix).
- Pas de propriétaire de session à vérifier puisqu'il n'y a pas d'auth pour
  l'instant (contrairement à l'ancien `OWNER_FILE`) — **mais** documenter
  clairement dans le code que si l'auth est ajoutée plus tard, ce contrôle
  devra être réintroduit avant toute exposition au-delà de localhost.

## Middleware de sécurité à mettre en place

- **Headers** : `Content-Security-Policy` strict (pas de `unsafe-inline`,
  cohérent avec un frontend statique sans JS inline — voir tâche 06),
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Permissions-Policy` restrictive. Pas de
  `Strict-Transport-Security` tant que le service est en HTTP pur localhost
  (HSTS sur du HTTP non-TLS n'a pas de sens, à ajouter le jour où un reverse
  proxy TLS est mis devant).
- **Limite de taille de requête** : `http.MaxBytesReader` sur tous les
  endpoints d'upload (conf SRX, CSV, export hitcount) — reprendre la limite
  de 32 Mo de l'ancien `app.py` comme point de départ, ajustable.
- **Validation de type de contenu uploadé** : vérifier que le fichier
  ressemble à un des formats attendus (XML/texte/CSV) *avant* de le passer au
  parser — rejeter early plutôt que laisser le parser XML avaler un binaire
  arbitraire. Pas de confiance dans l'extension de fichier fournie par le
  client, inspecter le contenu.
- **Rate limiting** : même en local, un token bucket simple par IP source
  (`golang.org/x/time/rate` ou implémentation maison) sur `/api/analyze` et
  les endpoints `rules/*`, pour éviter qu'un script buggé ou un usage
  concurrent mal maîtrisé ne sature les CPU (le parsing + génération XLSX
  n'est pas gratuit).
- **Timeouts** : `http.Server` avec `ReadTimeout`/`WriteTimeout`/
  `IdleTimeout` explicites (jamais les valeurs par défaut de Go, qui sont
  infinies).
- **Erreurs** : un seul type d'erreur HTTP exposée au client
  (`{"error": "message générique"}`), jamais de `err.Error()` brut d'un
  package interne renvoyé tel quel si ça peut contenir un chemin serveur ou
  une stack — logger le détail côté serveur (avec un request-id de
  corrélation), renvoyer un message stable côté client.
- **Pas de méthode HTTP dangereuse implicite** : router explicite par
  méthode, 405 sur le reste.
- **CORS** : désactivé par défaut (même origine que le frontend statique
  servi par le même binaire) — si un jour le frontend est servi séparément,
  whitelist explicite d'origine, jamais `*`.

## Livrables

- `internal/api/router.go`, `handlers_inventory.go`, `handlers_audit.go`,
  `handlers_rules.go`
- `internal/api/middleware.go` (headers, taille, rate limit, logging,
  recovery — un `recover()` global qui transforme toute panique en 500
  générique + log, jamais un crash du process sur une requête malformée)
- `internal/session/session.go`
- `cmd/server/main.go` (wiring, lecture de config via variables
  d'environnement : `SRXWEB_HOST`, `SRXWEB_PORT`, limites, TTL)
- Tests : au moins un test d'intégration HTTP par route (upload fixture →
  vérifie code de statut + structure de réponse), un test explicite de
  traversée de chemin (tentative avec `sid`/`fname` malveillants → doit
  retourner 404, jamais servir un fichier hors session), un test de dépassement
  de taille (doit rejeter proprement, pas OOM).

## Hors périmètre (assumé, à documenter dans le README du nouveau projet)

Pas d'authentification, pas de HTTPS natif (à faire via reverse proxy le jour
où le service sort de localhost — ne pas l'implémenter maintenant pour ne pas
donner un faux sentiment de sécurité avec un TLS auto-signé mal configuré).
