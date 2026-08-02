# srxtool — developer tasks
# Run `make help` for the list.

BINARY := srxtool-server
PKG    := ./...

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the server binary into bin/
	go build -trimpath -o bin/$(BINARY) ./cmd/server

.PHONY: run
run: ## Run the server locally on 127.0.0.1:8080
	SRXWEB_HOST=127.0.0.1 SRXWEB_PORT=8080 go run ./cmd/server

.PHONY: test
test: ## Run all tests with race detector and coverage
	go test $(PKG) -race -cover

.PHONY: fuzz
fuzz: ## Short fuzzing run against the config parser
	go test ./internal/config/... -fuzz=FuzzParse -fuzztime=30s

.PHONY: lint
lint: ## Static analysis: vet, staticcheck, gosec
	go vet $(PKG)
	go run honnef.co/go/tools/cmd/staticcheck@latest $(PKG)
	go run github.com/securego/gosec/v2/cmd/gosec@latest $(PKG)

.PHONY: vuln
vuln: ## Check dependencies against the Go vulnerability database
	go run golang.org/x/vuln/cmd/govulncheck@latest $(PKG)

.PHONY: check
check: test lint vuln ## Everything CI runs

.PHONY: docker-build
docker-build: ## Build the container image
	docker build -t srxtool-server:local .

.PHONY: up
up: ## Start the service via docker compose (localhost only)
	docker compose up --build

.PHONY: down
down: ## Stop the service
	docker compose down

.PHONY: clean
clean: ## Remove build output
	rm -rf bin/ dist/
