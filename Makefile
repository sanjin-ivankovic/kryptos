.PHONY: build run run-dry test cover lint validate clean tidy install download uninstall help
.DEFAULT_GOAL := help

BINARY  := kryptos
GOFLAGS := -trimpath

# --- Release install (downloads a published binary; no Go toolchain needed) ---
# Releases live only in Harbor, as one OCI artifact per tag holding every
# platform archive plus checksums.txt. oras pulls it anonymously
# (`brew install oras`).
OCI_REPO    := registry.example.com/example-org/kryptos/cli
# VERSION defaults to the newest release tag; override with `make install VERSION=v0.4.11`.
VERSION     ?= $(shell oras repo tags $(OCI_REPO) 2>/dev/null | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' | sort -V | tail -n1)
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

## install: pull + verify + install the released binary (latest, or VERSION=vX.Y.Z) to PREFIX/bin (default /usr/local)
install:
	@set -eu; \
	ver="$(VERSION)"; \
	[ -n "$$ver" ] || { echo "error: could not resolve a release VERSION (set VERSION=vX.Y.Z)"; exit 1; }; \
	command -v oras >/dev/null 2>&1 || { echo "error: oras is required (brew install oras)"; exit 1; }; \
	archive="$(BINARY)_$${ver#v}_$(OS)_$(ARCH).tar.gz"; \
	tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT; \
	echo "==> pulling $(OCI_REPO):$$ver ($(OS)/$(ARCH))"; \
	oras pull --output "$$tmp" "$(OCI_REPO):$$ver" >/dev/null; \
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

## download: pull + verify the released binary into ./ (no install; latest or VERSION=)
download:
	@set -eu; \
	ver="$(VERSION)"; \
	[ -n "$$ver" ] || { echo "error: could not resolve a release VERSION (set VERSION=vX.Y.Z)"; exit 1; }; \
	command -v oras >/dev/null 2>&1 || { echo "error: oras is required (brew install oras)"; exit 1; }; \
	archive="$(BINARY)_$${ver#v}_$(OS)_$(ARCH).tar.gz"; \
	tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT; \
	echo "==> pulling $(OCI_REPO):$$ver ($(OS)/$(ARCH))"; \
	oras pull --output "$$tmp" "$(OCI_REPO):$$ver" >/dev/null; \
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
