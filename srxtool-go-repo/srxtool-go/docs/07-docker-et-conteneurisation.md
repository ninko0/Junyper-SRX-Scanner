# 07 — Conteneurisation (`Dockerfile`, `docker-compose.yml`)

## Dépend de

Tâche 05 (le binaire doit exister, même incomplet) et tâche 06 pour les
assets statiques (si `embed` Go, ils sont déjà dans le binaire, sinon prévoir
leur copie dans l'image).

## But

Image Docker minimale, non-root, filesystem quasi-entièrement en lecture
seule, exposée uniquement sur `127.0.0.1` par défaut.

## Dockerfile — multi-stage

```dockerfile
# --- build stage ---
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/srxtool-server ./cmd/server

# --- final stage ---
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/srxtool-server /srxtool-server
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/srxtool-server"]
```

Points clés à respecter/adapter :
- **`distroless/static` ou `scratch`** : pas de shell, pas de gestionnaire de
  paquets, pas d'utilitaires système dans l'image finale — réduit
  drastiquement la surface d'attaque comparé à une image `alpine`/`debian`
  complète en prod. `distroless:nonroot` fournit déjà un utilisateur non-root
  par défaut (`USER nonroot` explicite quand même, par clarté).
- **`CGO_ENABLED=0`** : binaire statique, pas de dépendance à `libc` de
  l'image finale, compatible `scratch`.
- **`-trimpath -ldflags="-s -w"`** : retire les chemins de build absolus et
  les infos de debug du binaire — évite de fuiter la structure du filesystem
  de build.
- **`go.sum` vérifié** : `go mod download` doit utiliser le `go.sum` commité
  (intégrité des dépendances, équivalent du pinning `pip`).

## docker-compose.yml

```yaml
services:
  srxtool:
    build: .
    image: srxtool-server:local
    ports:
      - "127.0.0.1:8080:8080"     # localhost UNIQUEMENT, jamais 0.0.0.0
    environment:
      - SRXWEB_HOST=0.0.0.0        # à l'intérieur du conteneur, le bind interne peut être large ; c'est le mapping de port ci-dessus qui restreint réellement l'exposition
      - SRXWEB_PORT=8080
    read_only: true
    tmpfs:
      - /tmp/srxweb_sessions:size=256m,mode=1700
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    mem_limit: 512m
    pids_limit: 128
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "/srxtool-server", "-healthcheck"]  # ou wget si dispo, sinon un flag CLI dédié à ajouter au binaire
      interval: 30s
      timeout: 3s
      retries: 3
```

Points clés :
- **`ports: "127.0.0.1:8080:8080"`** — c'est le point le plus important pour
  respecter la contrainte "localhost uniquement" : sans le préfixe
  `127.0.0.1:`, Docker mappe par défaut sur `0.0.0.0` de l'hôte, ce qui expose
  le service à tout le réseau accessible à la VM. Documenter explicitement ce
  piège classique dans le README.
- **`read_only: true` + `tmpfs`** pour le répertoire de sessions — le
  conteneur ne peut écrire nulle part sauf ce volume en mémoire dédié,
  dimensionné et avec des permissions restrictives (`mode=1700`).
- **`cap_drop: ALL`** + **`no-new-privileges`** — durcissement standard,
  aucune capability Linux nécessaire pour un serveur HTTP applicatif pur Go.
- **Limites de ressources** (`mem_limit`, `pids_limit`) — protège contre un
  DoS local (upload répété de confs volumineuses générant beaucoup de
  parsing concurrent).
- Healthcheck : soit un endpoint `/healthz` interrogé via un binaire minimal
  inclus (pas de `curl`/`wget` dispo dans `distroless`), soit exposer un flag
  `-healthcheck` sur le binaire lui-même qui fait la requête en interne et sort
  avec le bon code retour — plus simple avec une image distroless sans
  outils réseau.

## `.dockerignore`

```
.git
*.md
testdata/golden
reference/
```

## Livrables

- `Dockerfile`
- `docker-compose.yml`
- `.dockerignore`
- Section README dédiée : comment builder, lancer, et **vérifier que le
  port n'est pas exposé au-delà de localhost** (`ss -tlnp | grep 8080` côté
  hôte, doit montrer `127.0.0.1:8080` et pas `0.0.0.0:8080` — même commande
  de vérification que pour l'ancienne version Python).

## Hors périmètre

Pas d'orchestration multi-conteneurs (pas de reverse proxy TLS dans ce
compose pour l'instant, cohérent avec "localhost only pour le moment") — à
ajouter dans une tâche ultérieure séparée le jour où le besoin d'exposition
réseau apparaît.
