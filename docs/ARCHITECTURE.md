# Architecture

Kryptos is a Go CLI/TUI that turns declarative YAML configs into Kubernetes
[SealedSecrets][sealed-secrets]. You describe an app's secrets once — fields,
generators, and derived values — and Kryptos builds the raw `Secret`, seals it
with `kubeseal`, and writes the `SealedSecret` into a GitOps tree.

It is **repo-agnostic**: a small `kryptos.toml` points it at any GitOps layout.
This repo is the **engine only** — the secret configs live in the consumer repo.

## Entry point and packages

Execution starts at [`main.go`](../main.go), which calls `cmd.Execute()`.

<!-- markdownlint-disable MD013 MD060 -->
| Package | Responsibility |
| --- | --- |
| `cmd/` | Cobra commands: root (TUI), `seal`, `add`, `rotate`, `validate`, `audit`, `diff`, plus `version`, `layout`, `dryrun` helpers |
| `internal/config/` | YAML app-config + TOML `kryptos.toml` layout parsing, validation, derive-reference checks |
| `internal/secrets/` | **UI-agnostic** pipeline: value resolution → derive → generate → seal → write |
| `internal/generator/` | Build the Kubernetes `Secret` and marshal the SealedSecret YAML |
| `internal/kubeseal/` | Thin wrapper around the `kubeseal` CLI (shell-out, connectivity check) |
| `internal/tui/` | Interactive workflow on the Charmbracelet stack (bubbletea / huh v2 / lipgloss v2) |
| `pkg/utils/` | Crypto + utility primitives: password/apikey/passphrase generators, bcrypt htpasswd, self-signed TLS, ed25519 keypair, template render, kubectl/file reads |
| `schema/` | `kryptos-v1.schema.json` — editor autocomplete/validation for configs |
| `templates/` | `kryptos-config.yaml` — annotated reference config |
<!-- markdownlint-enable MD013 MD060 -->

## The UI-agnostic pipeline

The seal flow lives in `internal/secrets/pipeline.go` and **never imports any
UI**. Front-ends inject behavior, so the TUI and the non-interactive CLI produce
identical sealed output from the same inputs:

- A **`ValueResolver`** func supplies non-derived field values. The TUI
  implements it with a huh form; the non-interactive path resolves by
  precedence: `--set` → `--values FILE` → env (`KRYPTOS_<SECRET>_<FIELD>`) →
  generator → default.
- **`Hooks`** (optional) let a front-end confirm overwrites and emit dry-run
  previews without the core knowing about a terminal.

When adding a command or front-end, reuse `Pipeline`/`ValueResolver` rather than
duplicating the resolve → derive → generate → seal → write logic.

## Generators and derived fields

**Generators** auto-create a field's value:

| Generator | Produces |
| --- | --- |
| `secure` | 32-character password |
| `strong` | 32-character password with symbols |
| `apikey` | 64-character hex API key |
| `passphrase` | 4-word passphrase |

**Derived fields** are computed after the form, before sealing. They run in two
passes (everything else first, then `render`) so a template can consume any
other derived value:

| Derive | Produces |
| --- | --- |
| `htpasswd` | `<user>:<bcrypt(value)>` |
| `cluster_secret` | a key read from a live `Secret` (`kubectl`) |
| `render` | a Go `text/template` over sibling field values |
| `jwt_secret` / `hmac` | a base64 random key (default 32 bytes) |
| `tls` | a self-signed cert + key (`<name>.crt` / `<name>.key`) |
| `ssh_keypair` | an ed25519 pair (`<name>` / `<name>.pub`) |
| `file` | the contents of a path |

Keep this table, the README's tables, and the `schema/kryptos-v1.schema.json`
enum in sync — they are a contract with config authors.

## Configuration layout (`kryptos.toml`)

`kryptos.toml` (in the consumer repo root) points Kryptos at that repo's layout.
All keys are optional with defaults: `config_dir`, `output_layout`, `sections`,
and `controller_namespace`. Per-app secret configs are validated against the
JSON schema and Kryptos's derive-reference checks before any sealing happens.

## Commands

<!-- markdownlint-disable MD013 -->
| Command | Behavior |
| --- | --- |
| `kryptos` | Interactive TUI (no subcommand) |
| `kryptos validate` | Validate every config; **no cluster needed** (CI-safe) |
| `kryptos --dry-run` | Preview without sealing or writing |
| `kryptos seal <app> <secret>` | Non-interactive seal (generators auto-fill; `--force` to re-seal) |
| `kryptos add <app> <secret> <field>` | Merge ONE field into an existing sealed secret |
| `kryptos rotate --app <a> --secret <s>` | Regenerate generators + recompute derives |
| `kryptos audit` | Configs that don't validate / are missing / orphaned |
| `kryptos diff [app]` | Per-secret structural drift (key set; values are encrypted) |
<!-- markdownlint-enable MD013 -->

`audit` and `diff` exit non-zero on any finding, so they gate CI. `kubeseal`
must be on `PATH` to seal; it is **not** needed for `validate` or `--dry-run`.

`seal` re-resolves every field, so re-sealing an existing secret regenerates
every `generator` field — silently rotating keys the caller never meant to
touch. It therefore refuses when the sealed file exists, listing what would be
regenerated, unless `--force` is given. `add` is the non-destructive path: it
seals one value and merges it in via `kubeseal --merge-into`, leaving every
other ciphertext byte-identical (`Pipeline.AddField` +
`Sealer.SealRawInto`).

## Release flow

Releases are SemVer git tags driven by [goreleaser](../.goreleaser.yaml).
Merging to `main` derives the next `vX.Y.Z` from the conventional-commit history
and pushes the tag; the tag pipeline cross-compiles `linux`/`darwin` ×
`amd64`/`arm64` and publishes a `tar.gz` + `checksums.txt` to the GitLab release
API. Consumers install a pinned binary with `make install`
(`VERSION=vX.Y.Z`) — no Go toolchain required.

[sealed-secrets]: https://github.com/bitnami-labs/sealed-secrets
