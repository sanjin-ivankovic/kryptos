# Contributing to Kryptos

Thank you for your interest in contributing. Kryptos is a portfolio project — a
Go CLI/TUI that generates Kubernetes [SealedSecrets][sealed-secrets] from
declarative YAML configs. While it is primarily a personal project, I welcome
contributions that improve documentation, fix bugs, or enhance overall quality.

Kryptos is the **engine only**: the secret configs it seals live in the consumer
repo, not here. Keep contributions generic and repo-agnostic — do not add
homelab-specific configs to this repository.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Contribution Workflow](#contribution-workflow)
- [Style Guidelines](#style-guidelines)
- [Testing Requirements](#testing-requirements)
- [Commit Message Conventions](#commit-message-conventions)
- [License](#license)

## Code of Conduct

This project follows a simple principle: **be respectful and constructive**.
We're all here to learn and improve.

## How Can I Contribute?

### Reporting Issues

If you find a bug, documentation error, or have a suggestion:

1. **Check existing issues** to avoid duplicates.
2. **Open a new issue** with a clear title, a description of the problem or
   suggestion, steps to reproduce (for bugs), expected vs actual behavior, and
   the Kryptos version (`kryptos version`) plus your OS/arch.

### Suggesting Enhancements

Enhancement suggestions are welcome. Please describe the use case, the proposed
behavior, and any alternatives you considered. New generators and derive types
should explain what they produce and why the existing set doesn't cover it.

### Pull Requests

Pull requests are welcome for documentation, bug fixes, new generators or derive
types, TUI improvements, and CI changes.

## Development Setup

### Prerequisites

- **Go 1.25+** (module `source.example.com/example-org/kryptos`).
- [`kubeseal`][kubeseal] — required to actually seal; **not** needed for
  `validate` or `--dry-run`.
- `pre-commit`, plus the shared linters it runs: `gitleaks`, `shellcheck`,
  `yamllint`, `markdownlint-cli2` (configured under [`.config/`](.config/)).
- `golangci-lint` (optional locally; `make lint` falls back to `go vet`).

### Local Environment

```bash
# Clone the repository
git clone <repo-url>
cd kryptos

# Install the pre-commit hooks (local dev gate; CI runs the same checks natively)
pre-commit install
pre-commit install --hook-type commit-msg
```

### Common Tasks (Makefile)

The compiled `./kryptos` binary is gitignored and built on demand — never commit
it.

```bash
make build      # compile the binary
make run        # build + run the interactive TUI (auto-detects config dir)
make run-dry    # build + run in dry-run mode
make test       # run unit tests with coverage
make cover      # write + open an HTML coverage report
make lint       # go vet (and golangci-lint / staticcheck if installed)
make validate   # validate all configs (no cluster needed)
make tidy       # tidy go modules
make clean      # remove build artefacts
make help       # list all targets
```

You can also use the Go toolchain directly: `go build ./...`, `go test ./...`,
`go vet ./...`, `go run . validate`.

## Contribution Workflow

1. **Branch** from `main` with a descriptive name (e.g. `feat/derive-x`,
   `fix/seal-overwrite`).
2. **Make focused changes.** Add a `*_test.go` beside any new behavior in
   `internal/` or `pkg/`.
3. **Run the checks** before pushing:

   ```bash
   make test
   make lint
   pre-commit run --all-files
   ```

4. **Open a merge request** against `main`. CI runs `scan:secrets`, `lint:go`,
   `test:go`, and `smoke:cli`; all must pass.
5. **Release is automated.** Merging to `main` derives the next SemVer tag from
   the conventional-commit history (see below) and a tag push runs goreleaser.
   See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the release flow.

## Style Guidelines

- Match the existing terse, operator-style code comments — explain **why**, not
  what.
- **Standard-library `testing` only** — no testify or third-party assertion
  libraries. Follow the existing table-driven test style.
- Mock external commands through the package-level seams (`execCommand`,
  `lookPath` in `internal/kubeseal` and `pkg/utils`); never shell out for real
  or require a live cluster in a unit test.
- Keep the UI-agnostic pipeline UI-free: front-ends inject behavior via
  `ValueResolver` and `Hooks` (see
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)).
- Keep the README feature/derive tables and the JSON schema enum in sync with
  `internal/secrets`, `pkg/utils`, and `schema/kryptos-v1.schema.json` — they
  are a contract.
- Never put real secrets, tokens, hostnames, or key material in code, tests,
  docs, or examples. Use placeholders.

## Testing Requirements

- Add or update tests for any behavior change; run `make test` (`go test ./...
  -cover`).
- The CLI smoke test (`go run . validate --help`) must keep passing.
- `audit` and `diff` exit non-zero on findings, so they gate CI — keep that
  contract intact.

## Commit Message Conventions

This repo uses [Conventional Commits][conventional]. Accepted types (enforced by
the `conventional-pre-commit` hook): `feat`, `fix`, `docs`, `refactor`, `chore`,
`test`, `ci`, `build`. Use a scope when it helps:

```text
feat(seal): resolve --set values before generators
fix(tui): stop overwriting an existing field on cancel
docs(readme): document the ssh_keypair derive
```

The conventional-commit **type drives the release**: a `feat` bumps the minor
version, a `fix` the patch, and a `feat!`/`BREAKING CHANGE` the major. Do not
add `Co-authored-by` trailers or mention AI assistance in commit messages.

## License

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).

[sealed-secrets]: https://github.com/bitnami-labs/sealed-secrets
[kubeseal]: https://github.com/bitnami-labs/sealed-secrets#kubeseal
[conventional]: https://www.conventionalcommits.org/
