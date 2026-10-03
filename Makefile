.PHONY: build run run-dry test cover lint validate clean tidy install download uninstall help

BINARY  := kryptos
GOFLAGS := -trimpath

# --- Release install (downloads a published binary; no Go toolchain needed) ---
# example-org/kryptos is PRIVATE on GitLab, so every API + asset request is
# token-authenticated. Export a GitLab personal access token with read_api
# scope as GITLAB_TOKEN, e.g. `GITLAB_TOKEN=<your-pat> make install`.
PROJECT_API := https://source.example.com/api/v4/projects/homelab%2Fkryptos
# VERSION defaults to the latest published release; override with `make install VERSION=v0.1.1`.
# GitLab returns releases newest-first as a JSON array (one line); the first
# tag_name is the latest. grep -o each match, then take the first.
VERSION     ?= $(shell curl -fsSL -H "PRIVATE-TOKEN: $(GITLAB_TOKEN)" "$(PROJECT_API)/releases" 2>/dev/null | grep -o '"tag_name":"[^"]*"' | head -n1 | sed 's/.*:"//; s/"$$//')
# Install location: `make install PREFIX=~/.local` → ~/.local/bin/kryptos.
PREFIX      ?= /usr/local
INSTALL_DIR := $(PREFIX)/bin
# Auto-detect platform (matches goreleaser's archive naming).
OS          := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH        := $(shell uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')

## build: compile the binary (NOT committed — gitignored; build or `go run .`)
build:
	go build $(GOFLAGS) -o $(BINARY) .

## run: build and run interactively (auto-detects config dir)
run: build
	./$(BINARY)

## run-dry: build and run in dry-run mode
run-dry: build
	./$(BINARY) --dry-run

## test: run unit tests with coverage
test:
	go test ./... -cover

## cover: write and open an HTML coverage report
cover:
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out

## lint: run go vet (and golangci-lint / staticcheck if installed)
lint:
	go vet ./...
	@if command -v golangci-lint > /dev/null 2>&1; then golangci-lint run ./...; \
	elif command -v staticcheck > /dev/null 2>&1; then staticcheck ./...; \
	else echo "golangci-lint/staticcheck not found, skipping"; fi

## validate: validate all configs (no cluster needed)
validate: build
	./$(BINARY) validate

## clean: remove build artefacts
clean:
	rm -f $(BINARY) coverage.out
	go clean ./...

## tidy: tidy go modules
tidy:
	go mod tidy

## install: download + verify + install the released binary (latest, or VERSION=vX.Y.Z) to PREFIX/bin (default /usr/local)
install:
	@set -eu; \
	ver="$(VERSION)"; \
	[ -n "$$ver" ] || { echo "error: could not resolve a release VERSION (set VERSION=vX.Y.Z)"; exit 1; }; \
	[ -n "$(GITLAB_TOKEN)" ] || { echo "error: GITLAB_TOKEN is required (example-org/kryptos is private; needs a read_api PAT)"; exit 1; }; \
	archive="$(BINARY)_$${ver#v}_$(OS)_$(ARCH).tar.gz"; \
	base="$(PROJECT_API)/releases/$$ver/downloads"; \
	tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT; \
	echo "==> downloading $$archive ($$ver, $(OS)/$(ARCH))"; \
	curl -fsSL -H "PRIVATE-TOKEN: $(GITLAB_TOKEN)" "$$base/$$archive"      -o "$$tmp/$$archive"; \
	curl -fsSL -H "PRIVATE-TOKEN: $(GITLAB_TOKEN)" "$$base/checksums.txt"  -o "$$tmp/checksums.txt"; \
	echo "==> verifying checksum"; \
	( cd "$$tmp" && grep " $$archive$$" checksums.txt | { \
	    if command -v sha256sum >/dev/null 2>&1; then sha256sum -c -; \
	    else shasum -a 256 -c -; fi; } ); \
	echo "==> extracting"; \
	tar -xzf "$$tmp/$$archive" -C "$$tmp" $(BINARY); \
	if [ -w "$(INSTALL_DIR)" ]; then \
	    install -m 0755 "$$tmp/$(BINARY)" "$(INSTALL_DIR)/$(BINARY)"; \
	else \
	    echo "==> $(INSTALL_DIR) not writable; using sudo"; \
	    sudo install -m 0755 "$$tmp/$(BINARY)" "$(INSTALL_DIR)/$(BINARY)"; \
	fi; \
	echo "==> installed: $$($(INSTALL_DIR)/$(BINARY) version)"

## download: fetch + verify the released binary into ./ (no install; latest or VERSION=)
download:
	@set -eu; \
	ver="$(VERSION)"; \
	[ -n "$$ver" ] || { echo "error: could not resolve a release VERSION (set VERSION=vX.Y.Z)"; exit 1; }; \
	[ -n "$(GITLAB_TOKEN)" ] || { echo "error: GITLAB_TOKEN is required (example-org/kryptos is private; needs a read_api PAT)"; exit 1; }; \
	archive="$(BINARY)_$${ver#v}_$(OS)_$(ARCH).tar.gz"; \
	base="$(PROJECT_API)/releases/$$ver/downloads"; \
	tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT; \
	echo "==> downloading $$archive ($$ver, $(OS)/$(ARCH))"; \
	curl -fsSL -H "PRIVATE-TOKEN: $(GITLAB_TOKEN)" "$$base/$$archive"     -o "$$tmp/$$archive"; \
	curl -fsSL -H "PRIVATE-TOKEN: $(GITLAB_TOKEN)" "$$base/checksums.txt" -o "$$tmp/checksums.txt"; \
	( cd "$$tmp" && grep " $$archive$$" checksums.txt | { \
	    if command -v sha256sum >/dev/null 2>&1; then sha256sum -c -; \
	    else shasum -a 256 -c -; fi; } ); \
	tar -xzf "$$tmp/$$archive" -C . $(BINARY); \
	echo "==> ./$(BINARY) ($$ver) ready"

## uninstall: remove the installed binary from PREFIX/bin
uninstall:
	@if [ -w "$(INSTALL_DIR)" ]; then rm -f "$(INSTALL_DIR)/$(BINARY)"; \
	else sudo rm -f "$(INSTALL_DIR)/$(BINARY)"; fi; \
	echo "==> removed $(INSTALL_DIR)/$(BINARY)"

## help: show this help message
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /' | column -t -s ':'
