# 08 — Tests, fuzzing & CI (`.github/workflows/ci.yml`)

## Dépend de

Tâche 01 au minimum pour démarrer (le parser est la surface la plus critique
à fuzzer, puisqu'il ingère des données non fiables). À enrichir au fur et à
mesure des autres tâches plutôt que d'attendre la fin du projet.

## But

Garantir la non-régression fonctionnelle (parité avec le Python) et la
robustesse face à des entrées malformées/malveillantes.

## Stratégie de test par niveau

1. **Unitaire par package** — chaque fonction de `config`, `inventory`,
   `audit`, `rules` testée isolément avec des cas nominaux + cas limites
   (déjà détaillé dans les tâches 01-04 respectives).
2. **Golden files** — sorties JSON/texte figées à partir des fixtures
   existantes (`sample.xml`, `sample2.txt`, `sample-show-config.txt`) et des
   sorties Python déjà produites et fournies dans le projet (`audit.json`,
   `inv.json`, `rename-plan.csv`). Un test qui échoue si la sortie Go diverge
   d'un seul champ de ces golden files, sauf divergence **documentée et
   volontaire** (voir tâche 09).
3. **Tests d'intégration HTTP** — un par route de l'API (tâche 05), avec
   client `net/http/httptest`, fixtures uploadées en multipart.
4. **Fuzzing (Go natif, `testing.F`)** — cible prioritaire :
   `internal/config` (les 3 parseurs). Un fuzzer qui prend un `[]byte`
   arbitraire, tente les 3 parseurs, et vérifie uniquement l'absence de
   panique/de boucle infinie/de consommation mémoire excessive (pas la
   correction du résultat, juste la robustesse). Corpus de départ : les
   fixtures existantes. À exécuter en CI en mode court (`-fuzztime=30s`) et
   ponctuellement en local en mode long.
5. **Analyse statique de sécurité** :
   - `govulncheck` (scan des CVE connues sur les dépendances et la stdlib
     utilisée)
   - `gosec` (patterns de code Go à risque : injection, gestion de fichiers,
     crypto faible, etc.)
   - `go vet` + `staticcheck` (qualité générale)
6. **Test explicite de traversée de chemin** (déjà mentionné en tâche 05,
   listé ici aussi car c'est un test de sécurité, pas juste fonctionnel) :
   tentatives avec `sid`/`fname` contenant `..`, encodage URL, chemins
   absolus — doivent toutes échouer proprement (404), jamais servir un fichier
   hors du répertoire de session.

## Pipeline CI (exemple GitHub Actions, adapter à la plateforme réellement
utilisée si différente)

```yaml
name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }
      - run: go build ./...
      - run: go vet ./...
      - run: go test ./... -race -cover
      - run: go test ./internal/config/... -fuzz=FuzzParse -fuzztime=30s
      - run: go run golang.org/x/vuln/cmd/govulncheck@latest ./...
      - run: go run github.com/securego/gosec/v2/cmd/gosec@latest ./...
  docker:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t srxtool-server:ci .
      - run: docker run --rm srxtool-server:ci -version   # sanity check que l'image démarre
```

## Livrables

- `.github/workflows/ci.yml` (ou équivalent GitLab CI/autre selon la
  plateforme réelle)
- `internal/config/fuzz_test.go`
- Un script ou Makefile (`Makefile` avec cibles `test`, `fuzz`, `lint`,
  `docker-build`) pour reproduire la CI en local facilement.

## Hors périmètre

Pas de tests de charge/performance formalisés à ce stade (outil interne,
volumétrie faible) — à ajouter si l'usage évolue.
