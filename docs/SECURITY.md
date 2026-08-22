# Security Model

Kryptos generates and seals secrets but **stores none**. This document explains
what is and isn't sensitive, how the sealing trust model works, and the security
implications of each command.

## What Kryptos handles

- **Plaintext, transiently.** During a seal, Kryptos holds field values in
  memory long enough to build a Kubernetes `Secret`, pipe it through `kubeseal`,
  and discard it. Plaintext is never written to disk.
- **SealedSecrets, persistently.** The only output committed to a GitOps tree is
  the `SealedSecret` — an encrypted blob that is safe to store in Git.
- **No state of its own.** Kryptos keeps no database, cache, or credential
  store. The config files describe the *shape* of secrets (field names,
  generators, derives), not their values.

## Sealing trust model

Sealing is delegated to [`kubeseal`][kubeseal] and the in-cluster
[Sealed Secrets controller][sealed-secrets]:

- `kubeseal` encrypts with the controller's **public** key, so sealing needs no
  cluster secrets — only network reach to fetch the cert (or an offline cert).
- Only the controller's **private** key (held in the cluster) can decrypt. The
  sealed blob is bound to a namespace/name by default, so it cannot be
  re-used elsewhere.
- `kubeseal` is required to seal. It is **not** needed for `validate` or
  `--dry-run`, which never touch ciphertext — keep CI on those cluster-free
  paths.

## Generated material

Generators and derives produce material with these properties:

- `secure` / `strong` — 32-character passwords (`strong` adds symbols).
- `apikey` — 64-character hex (32 bytes of entropy).
- `passphrase` — a 4-word passphrase.
- `jwt_secret` / `hmac` — base64 random keys (default 32 bytes).
- `tls` — a self-signed certificate + key (for internal/testing use, not a CA
  chain).
- `ssh_keypair` — an ed25519 key pair.
- `htpasswd` — a bcrypt hash of a value (the plaintext is not retained).

Random material comes from Go's `crypto/rand`. Do not weaken a generator to make
output reproducible; reproducibility belongs in `--dry-run` previews, not in the
key material.

## `audit` and `diff` exposure

`audit` and `diff` are designed to be safe to run and to surface in CI:

- `diff` reports **structural** drift — the *set of keys* in a config versus the
  sealed file on disk. It does **not** decrypt values (it can't; only the
  cluster can).
- `audit` flags configs that fail validation, are missing, or have orphaned
  sealed files.
- Both exit non-zero on findings, so they gate a pipeline without ever printing
  secret values.

## Handling secrets in this repo

- Never commit real secrets, tokens, hostnames, or private key material — not in
  code, tests, docs, or example configs. Use placeholders.
- The repo's `gitleaks` scan (CI `scan:secrets` + the pre-commit hook) runs over
  full history as a backstop; the `.config/.gitleaks.toml` ruleset allowlists
  only the test fixtures and example shapes that legitimately look secret-like.
- Tests use synthetic values and mock `kubeseal`/`kubectl` through package-level
  seams — a unit test never reaches a real cluster or key.

## Reporting a vulnerability

Open an issue describing the problem and impact. Do not include a working
exploit or any real secret material in the report.

[sealed-secrets]: https://github.com/bitnami-labs/sealed-secrets
[kubeseal]: https://github.com/bitnami-labs/sealed-secrets#kubeseal
