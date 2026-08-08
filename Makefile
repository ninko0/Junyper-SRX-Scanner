# Development targets — task 08's CI replays the same ones.
GO ?= go

.PHONY: build test race fuzz fuzz-rules lint golden golden-audit clean vuln sec docker-build

build:
	$(GO) build ./...

test:
	$(GO) test ./... -cover

race:
	$(GO) test ./... -race

fuzz:
	$(GO) test ./internal/config/ -run=FuzzParse -fuzz=FuzzParse -fuzztime=30s

fuzz-rules:
	$(GO) test ./internal/rules/ -run=FuzzParseHitcount -fuzz=FuzzParseHitcount -fuzztime=20s
	$(GO) test ./internal/rules/ -run=FuzzReadRenameMapCSV -fuzz=FuzzReadRenameMapCSV -fuzztime=20s

lint:
	$(GO) vet ./...
	gofmt -l .

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

sec:
	$(GO) run github.com/securego/gosec/v2/cmd/gosec@latest ./...

# Regenerates the golden files from the reference Python (reference/).
golden:
	python3 scripts/gen_golden_model.py

golden-audit:
	python3 scripts/gen_golden_audit.py

docker-build:
	docker build -t srxtool-server:local .

clean:
	$(GO) clean -testcache
