# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
#
# kryptos-ci — CI tools image for the kryptos Go CLI.
#
# Version model DIVERGES from the other three CI images ON PURPOSE: kryptos's
# build context is .ci/docker only, so it pins tools here as ARG defaults with
# `# renovate:` annotations (the GitLab CI build:ci-image job passes NO
# --build-arg). Don't "align" it to the build-arg model without moving the
# pins. See the README.
#
# Non-obvious by design (don't "fix"):
#   - runs as root, no USER/HEALTHCHECK — ephemeral CI pods, root-writable cache
#   - golang base carries tag@sha256:<digest> so Renovate pins the digest too
#   - this image carries cosign; the GitLab CI sign:ci-image job runs cosign
#     FROM this image to sign the image itself by digest (key = COSIGN_KEY)

# renovate: datasource=docker depName=golang versioning=docker
ARG GO_VERSION=1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2

# Tool versions — declared before the fetcher so both stages consume them.
# renovate: datasource=github-releases depName=goreleaser/goreleaser
ARG GORELEASER_VERSION=v2.17.0
# renovate: datasource=github-releases depName=golangci/golangci-lint
ARG GOLANGCI_LINT_VERSION=v2.12.2
# renovate: datasource=github-releases depName=gitleaks/gitleaks
ARG GITLEAKS_VERSION=v8.30.1
# renovate: datasource=github-releases depName=sigstore/cosign
ARG COSIGN_VERSION=v3.1.2
# renovate: datasource=github-releases depName=oras-project/oras
ARG ORAS_VERSION=v1.3.3
# renovate: datasource=go depName=github.com/boumenot/gocover-cobertura
ARG GOCOVER_COBERTURA_VERSION=v1.5.0
# renovate: datasource=go depName=gotest.tools/gotestsum
ARG GOTESTSUM_VERSION=v1.13.0

# fetcher: download + checksum-verify each binary, one RUN per tool. curl/tar/xz
# live here only. uname-based arch keeps the image buildable on amd64 + arm64.
FROM golang:${GO_VERSION} AS fetcher
ARG GORELEASER_VERSION
ARG GOLANGCI_LINT_VERSION
ARG GITLEAKS_VERSION
ARG COSIGN_VERSION
ARG ORAS_VERSION

RUN apk add --no-cache curl tar xz && mkdir -p /out/usr/local/bin

# goreleaser — release the cross-platform binaries on a tag. Verified against
# the release checksums.txt.
RUN GORELEASER_ARCH="$(uname -m | sed 's/aarch64/arm64/; s/x86_64/x86_64/')" && \
  curl -fsSL "https://github.com/goreleaser/goreleaser/releases/download/${GORELEASER_VERSION}/goreleaser_Linux_${GORELEASER_ARCH}.tar.gz" -o /tmp/goreleaser.tgz && \
  curl -fsSL "https://github.com/goreleaser/goreleaser/releases/download/${GORELEASER_VERSION}/checksums.txt" \
    | grep "goreleaser_Linux_${GORELEASER_ARCH}.tar.gz$" | awk '{print $1"  /tmp/goreleaser.tgz"}' | sha256sum -c - && \
  tar xz -f /tmp/goreleaser.tgz -C /out/usr/local/bin goreleaser && \
  /out/usr/local/bin/goreleaser --version

# golangci-lint — bundles vet + staticcheck (matches local `make lint`).
RUN GOLANGCI_ARCH="$(uname -m | sed 's/aarch64/arm64/; s/x86_64/amd64/')" && \
  GOLANGCI_DIR="golangci-lint-${GOLANGCI_LINT_VERSION#v}-linux-${GOLANGCI_ARCH}" && \
  curl -fsSL "https://github.com/golangci/golangci-lint/releases/download/${GOLANGCI_LINT_VERSION}/${GOLANGCI_DIR}.tar.gz" -o /tmp/golangci.tgz && \
  curl -fsSL "https://github.com/golangci/golangci-lint/releases/download/${GOLANGCI_LINT_VERSION}/golangci-lint-${GOLANGCI_LINT_VERSION#v}-checksums.txt" \
    | grep "${GOLANGCI_DIR}.tar.gz$" | awk '{print $1"  /tmp/golangci.tgz"}' | sha256sum -c - && \
  tar xz -f /tmp/golangci.tgz -C /tmp && \
  mv "/tmp/${GOLANGCI_DIR}/golangci-lint" /out/usr/local/bin/ && \
  /out/usr/local/bin/golangci-lint version

RUN GITLEAKS_ARCH="$(uname -m | sed 's/aarch64/arm64/; s/x86_64/x64/')" && \
  curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_${GITLEAKS_ARCH}.tar.gz" -o /tmp/gitleaks.tgz && \
  curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_checksums.txt" \
    | grep "gitleaks_${GITLEAKS_VERSION#v}_linux_${GITLEAKS_ARCH}.tar.gz$" | awk '{print $1"  /tmp/gitleaks.tgz"}' | sha256sum -c - && \
  tar xz -f /tmp/gitleaks.tgz -C /out/usr/local/bin gitleaks && \
  /out/usr/local/bin/gitleaks version

# cosign — signs the CI image (via cosign-sign-image-step).
RUN COSIGN_ARCH="$(uname -m | sed 's/aarch64/arm64/; s/x86_64/amd64/')" && \
  curl -fsSL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-${COSIGN_ARCH}" -o /out/usr/local/bin/cosign && \
  curl -fsSL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign_checksums.txt" \
    | grep "cosign-linux-${COSIGN_ARCH}$" | awk '{print $1"  /out/usr/local/bin/cosign"}' | sha256sum -c - && \
  chmod +x /out/usr/local/bin/cosign && \
  /out/usr/local/bin/cosign version

# oras — pushes the released archive to Harbor as an OCI artifact
# (publish:oci), the tokenless distribution channel consumers pull with
# Harbor credentials instead of a GitLab read PAT.
RUN ORAS_ARCH="$(uname -m | sed 's/aarch64/arm64/; s/x86_64/amd64/')" && \
  curl -fsSL "https://github.com/oras-project/oras/releases/download/${ORAS_VERSION}/oras_${ORAS_VERSION#v}_linux_${ORAS_ARCH}.tar.gz" -o /tmp/oras.tgz && \
  curl -fsSL "https://github.com/oras-project/oras/releases/download/${ORAS_VERSION}/oras_${ORAS_VERSION#v}_checksums.txt" \
    | grep "oras_${ORAS_VERSION#v}_linux_${ORAS_ARCH}.tar.gz$" | awk '{print $1"  /tmp/oras.tgz"}' | sha256sum -c - && \
  tar xz -f /tmp/oras.tgz -C /out/usr/local/bin oras && \
  /out/usr/local/bin/oras version

# --- final image ---
FROM golang:${GO_VERSION}
ARG GOCOVER_COBERTURA_VERSION
ARG GOTESTSUM_VERSION

LABEL maintainer="maintainer@example.io"
LABEL org.opencontainers.image.title="kryptos-ci"
LABEL org.opencontainers.image.description="CI tools for the kryptos Go CLI (Go, goreleaser, golangci-lint, gitleaks, cosign, oras, gotestsum, gocover-cobertura)"
LABEL org.opencontainers.image.source="https://source.example.com/example-org/kryptos"
LABEL org.opencontainers.image.licenses="MIT"

# Runtime only — no curl (fetcher does downloads). git is needed by goreleaser
# (tag/commit metadata) and the gitleaks git-history scan. No python/pre-commit:
# CI runs golangci-lint / go test / gitleaks / cosign / goreleaser directly;
# pre-commit is a LOCAL-only dev hook (not run in CI).
RUN apk add --no-cache \
  bash git jq grep ca-certificates openssh-client

COPY --from=fetcher /out/usr/local/bin/ /usr/local/bin/

# Go-module tools: `go install` (module proxy + go.sum is the integrity check,
# so the fetcher's checksums.txt pattern doesn't apply). gotestsum emits junit,
# gocover-cobertura converts the coverage profile — both feed GitLab's MR widgets.
RUN go install "github.com/boumenot/gocover-cobertura@${GOCOVER_COBERTURA_VERSION}" && \
  go install "gotest.tools/gotestsum@${GOTESTSUM_VERSION}" && \
  mv "$(go env GOPATH)/bin/gocover-cobertura" "$(go env GOPATH)/bin/gotestsum" /usr/local/bin/ && \
  rm -rf "$(go env GOPATH)/pkg/mod" "$(go env GOCACHE)"

# Smoke-test every tool at build so a broken install fails here, not in CI.
RUN echo "=== Installed Tools ===" && \
  echo "go: $(go version)" && \
  echo "goreleaser: $(goreleaser --version 2>&1 | awk '/GitVersion:/{print $2}')" && \
  echo "golangci-lint: $(golangci-lint version 2>&1 | head -n1)" && \
  echo "gitleaks: $(gitleaks version)" && \
  echo "cosign: $(cosign version 2>&1 | awk '/^GitVersion:/{print $2}')" && \
  echo "oras: $(oras version 2>&1 | awk '/^Version:/{print $2}')" && \
  echo "gotestsum: $(gotestsum --version)" && \
  echo "gocover-cobertura: $(command -v gocover-cobertura)" && \
  echo "git: $(git --version)" && \
  echo "======================="

WORKDIR /workspace
CMD ["/bin/bash"]
