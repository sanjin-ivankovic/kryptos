# Kryptos 🔐

Kryptos is a CLI + TUI for generating Kubernetes
[SealedSecrets](https://github.com/bitnami-labs/sealed-secrets) from declarative
YAML configs. You describe each app's secrets once — fields, generators, and
computed values — and Kryptos builds the raw Secret, seals it with `kubeseal`,
and writes the SealedSecret into your GitOps tree.

It's repo-agnostic: point it at any GitOps layout with a small `kryptos.toml`.

## Features

- **Interactive TUI** — pick an app, pick secrets, fill or auto-generate values.
- **Generators** — `secure` / `strong` / `apikey` / `passphrase` values, no
  manual entropy.
- **Derived fields** — compute a value instead of typing it: `htpasswd`,
  `cluster_secret` (read a live Secret), `render` (Go template over siblings),
  `jwt_secret` / `hmac`, `tls` (self-signed cert+key), `ssh_keypair`, `file`.
- **`validate`** — catch config mistakes (bad names, dup keys, broken derives)
  with no cluster access — CI/pre-commit friendly.
- **`audit` / `diff`** — find drift between configs and the sealed files on
  disk.
- **`seal` / `rotate`** — non-interactive, CI-driven sealing and coordinated
  secret rotation.
- **`add`** — merge ONE new field into an already-sealed secret, leaving every
  other key's ciphertext untouched.
- **JSON schema** — editor autocomplete + validation via a
  `yaml-language-server` modeline.

## Install

Install the latest released binary (auto-detects OS/arch, verifies the
checksum, installs to `/usr/local/bin`). `example-org/kryptos` is **private** on
GitLab, so the install/download targets need a GitLab personal access token
with `read_api` scope exported as `GITLAB_TOKEN`:

```bash
GITLAB_TOKEN=<your-pat>            # GitLab PAT with read_api scope
make install                      # latest release
make install VERSION=v0.1.1       # a specific version
make install PREFIX=~/.local      # install to ~/.local/bin (no sudo)
make download                     # fetch + verify into ./ without installing
make uninstall                    # remove it
```

Or grab a tarball from the private
[releases page](https://source.example.com/example-org/kryptos/-/releases) (sign in to
GitLab), or build from source (Go 1.25+):

```bash
git clone https://source.example.com/example-org/kryptos.git
cd kryptos
make build      # → ./kryptos
```

`kubeseal` must be on your `PATH` to seal (not needed for `validate` /
`--dry-run`).

## Quick start

```bash
kryptos                       # interactive TUI
kryptos validate              # check every config (no cluster needed)
kryptos --dry-run             # preview without sealing or writing
```

## Configuring secrets

Each app is a YAML file in your config dir. Minimal example:

```yaml
# yaml-language-server: $schema=https://source.example.com/example-org/kryptos/-/raw/main/schema/kryptos-v1.schema.json
apiVersion: kryptos.dev/v1
kind: SecretConfig
metadata:
  name: myapp
  namespace: myapp
spec:
  secrets:
    - name: myapp-secret
      type: Opaque
      fields:
        - name: password
          generator: secure       # auto-generated 32-char password
          required: true
        - name: token
          derive: jwt_secret      # base64 random signing key
```

<!-- markdownlint-disable MD013 -->
See [`templates/kryptos-config.yaml`](templates/kryptos-config.yaml) for a fully
annotated reference and [`schema/kryptos-v1.schema.json`](schema/kryptos-v1.schema.json)
for the complete field list.
<!-- markdownlint-enable MD013 -->

### Derived fields

A field can be computed instead of prompted (after the form, before sealing):

<!-- markdownlint-disable MD013 MD060 -->
| `derive`         | Produces                                                        |
| ---------------- | -------------------------------------------------------------- |
| `htpasswd`       | `<derive_username>:<bcrypt(derive_from)>`                       |
| `cluster_secret` | a key read from a live Secret (`kubectl`)                      |
| `render`         | a Go `text/template` over sibling field values                 |
| `jwt_secret` / `hmac` | a base64 random key (default 32 bytes)                    |
| `tls`            | a self-signed cert+key into `<name>.crt` / `<name>.key`        |
| `ssh_keypair`    | an ed25519 pair into `<name>` / `<name>.pub`                   |
| `file`           | the contents of `derive_path`                                  |
<!-- markdownlint-enable MD013 MD060 -->

Derives run in two passes (everything, then `render`), so a template can consume
any other derived value — e.g. rotate a password and its `htpasswd` recomputes
in the same run.

## Pointing Kryptos at your repo (`kryptos.toml`)

By default Kryptos expects a `tools/kryptos/configs/` config dir and writes to
`cluster/{apps,infrastructure}/<app>/secrets/`. Override with a `kryptos.toml`
at your repo root:

```text
config_dir           = "secrets/configs"
output_layout        = "manifests/{section}/{app}/sealed/{name}"
sections             = ["base", "overlays"]
controller_namespace = "kube-system"
```

Every field is optional and falls back to the default, so no `kryptos.toml` is
needed for the default layout.

## Inspecting drift

```bash
kryptos audit        # configs that don't validate, secrets with no sealed file,
                     # and orphaned *-sealed-secret.yaml files
kryptos diff [app]   # per-secret STRUCTURAL drift (key set, since values are
                     # encrypted): + key missing from the sealed file, - orphaned
```

Both exit non-zero on any finding, so they gate CI.

## Non-interactive seal & rotate

```bash
kryptos seal myapp myapp-secret                       # generator auto-fills
kryptos seal myapp --all --set password=...           # seal every secret
kryptos rotate --app myapp --secret myapp-secret      # regenerate + reseal
```

`seal` resolves each field by precedence: `--set`, then `--values FILE`, then
the environment (`KRYPTOS_<SECRET>_<FIELD>`), then the field's generator, then
its default. A required field with none is a hard error. The sealed output is
identical to the interactive path for the same inputs.

`rotate` regenerates a secret's generator field(s) and recomputes derives.
Because sealed values are encrypted at rest, any non-rotated required field must
be supplied with `--set` / `--values`.

## Adding a field to an existing secret

**Do not re-seal a secret just to add a field.** `seal` re-resolves *every*
field, so every field carrying a `generator` gets a NEW random value — adding
one key by re-sealing silently rotates all the others, and sealed values cannot
be read back to restore them. Use `add`:

```bash
kryptos add myapp myapp-secret new.field --set new.field=value
kryptos add myapp myapp-secret new.token          # generator auto-fills
```

`add` encrypts the single value and merges it into the existing SealedSecret
file (`kubeseal --merge-into`); every other key's ciphertext stays
byte-identical. Values resolve by the same precedence `seal` uses.

It refuses, rather than risking data loss, when:

| Condition                  | Why                                          |
| -------------------------- | -------------------------------------------- |
| the sealed file is missing | nothing to merge into; run `seal` first      |
| the field isn't declared   | a typo would create an orphan key            |
| the field has a `derive:`  | it's computed from siblings; re-seal instead |
| the key is already sealed  | re-adding rotates it (`--force` overrides)   |

To match, `seal` refuses to overwrite an existing sealed file. It first
lists which keys a re-seal would regenerate versus preserve, and points at
`add`. Pass `--force` to re-seal anyway (CI included). The interactive TUI
offers the same choice — "add a single field" or "re-seal everything" — whenever
a selected secret is already sealed.

## Development

```bash
make build      # compile ./kryptos (gitignored, never committed)
make test       # go test ./... -cover
make lint       # go vet (+ golangci-lint if installed)
make validate   # validate every config in the config dir
```

The binary is built on demand, never committed. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow, style, and
commit/release conventions.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — package layout, the UI-agnostic
  seal pipeline, generators/derives, commands, and the release flow.
- [docs/SECURITY.md](docs/SECURITY.md) — the encryption/trust model and the
  `audit`/`diff` exposure guarantees.

## License

[MIT](LICENSE)
