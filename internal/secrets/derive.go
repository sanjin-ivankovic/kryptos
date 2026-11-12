// Package secrets holds the kryptos secret-generation core, decoupled from the
// interactive TUI. It generates field values, applies the derive pipeline,
// builds the raw Kubernetes Secret, seals it, and writes the SealedSecret —
// driven by a swappable ValueResolver so the interactive (huh) and
// non-interactive (--values/flags) front-ends share one implementation.
package secrets

import (
	"fmt"
	"strings"

	"source.example.com/example-org/kryptos/internal/config"
	"source.example.com/example-org/kryptos/pkg/utils"
)

// GenerateFieldValue auto-generates a value for a field based on its Generator
// directive. Returns "" if the field should receive caller-supplied input.
func GenerateFieldValue(field config.SecretField) (string, error) {
	length := field.Length
	switch field.Generator {
	case "secure":
		if length == 0 {
			length = 32
		}
		return utils.GenerateSecurePassword(length, false)
	case "strong":
		if length == 0 {
			length = 32
		}
		return utils.GenerateSecurePassword(length, true)
	case "apikey":
		if length == 0 {
			length = 64
		}
		return utils.GenerateAPIKey(length)
	case "passphrase":
		return utils.GeneratePassphrase(4, "-")
	default:
		return "", nil
	}
}

// ExpandMagicKeyword replaces a magic keyword (secure/strong/apikey/passphrase)
// supplied as a value with a freshly generated value; any other value passes
// through unchanged.
func ExpandMagicKeyword(val string, field config.SecretField) (string, error) {
	length := field.Length
	switch strings.TrimSpace(val) {
	case "secure":
		if length == 0 {
			length = 32
		}
		return utils.GenerateSecurePassword(length, false)
	case "strong":
		if length == 0 {
			length = 32
		}
		return utils.GenerateSecurePassword(length, true)
	case "apikey":
		if length == 0 {
			length = 64
		}
		return utils.GenerateAPIKey(length)
	case "passphrase":
		return utils.GeneratePassphrase(4, "-")
	default:
		return val, nil
	}
}

// ApplyDerivedFields computes values for any field with a Derive directive,
// mutating data in place.
//
// Two passes:
//  1. cluster_secret + htpasswd + jwt_secret/hmac + tls/ssh_keypair + file —
//     these depend only on already-resolved siblings (form input, earlier
//     lookups, or nothing), so they run in declaration order.
//  2. render — runs last, after every other field is populated, so its
//     Go-template body can reference any sibling.
//
// Supported derivations:
//
//	htpasswd        "<derive_username>:<bcrypt(data[derive_from])>"
//	cluster_secret  read a key from a live cluster Secret (kubectl)
//	jwt_secret      a base64 random key (alias of hmac), default 32 bytes
//	hmac            a base64 random key, default 32 bytes (override via length)
//	tls             a self-signed cert+key pair (writes <name>.crt/.key siblings)
//	ssh_keypair     an ed25519 SSH key pair (writes <name> + <name>.pub siblings)
//	file            the contents of the file at derive_path
//	render          a Go text/template over sibling values
//
// When dryRun is true, cluster_secret derives DO NOT contact the cluster: they
// emit a "<cluster:namespace/secret.key>" placeholder so a dry-run never needs
// kubectl or auth. All other derives still compute normally.
func ApplyDerivedFields(secret *config.Secret, data map[string]string, dryRun bool) error {
	// Pass 1: everything except render.
	for _, field := range secret.Fields {
		if field.Derive == "" || field.Derive == "render" {
			continue
		}
		if err := applyPass1Derive(field, data, dryRun); err != nil {
			return err
		}
	}

	// Pass 2: render templates after every other field is resolved.
	for _, field := range secret.Fields {
		if field.Derive != "render" {
			continue
		}
		if field.DeriveTemplate == "" {
			return fmt.Errorf("field %q: derive=render requires derive_template", field.Name)
		}
		rendered, err := utils.RenderTemplate(field.DeriveTemplate, data)
		if err != nil {
			return fmt.Errorf("field %q: %w", field.Name, err)
		}
		data[field.Name] = rendered
	}
	return nil
}

// applyPass1Derive handles a single non-render derive field.
func applyPass1Derive(field config.SecretField, data map[string]string, dryRun bool) error {
	switch field.Derive {
	case "htpasswd":
		return deriveHtpasswd(field, data)
	case "cluster_secret":
		return deriveClusterSecret(field, data, dryRun)
	case "jwt_secret", "hmac":
		return deriveRandomKey(field, data)
	case "tls":
		return deriveTLS(field, data)
	case "ssh_keypair":
		return deriveSSHKeypair(field, data)
	case "file":
		return deriveFile(field, data)
	default:
		return fmt.Errorf("field %q: unknown derive type %q (supported: htpasswd, cluster_secret, jwt_secret, hmac, tls, ssh_keypair, file, render)",
			field.Name, field.Derive)
	}
}

func deriveHtpasswd(field config.SecretField, data map[string]string) error {
	if field.DeriveFrom == "" {
		return fmt.Errorf("field %q: derive=htpasswd requires derive_from", field.Name)
	}
	if field.DeriveUsername == "" {
		return fmt.Errorf("field %q: derive=htpasswd requires derive_username", field.Name)
	}
	source, ok := data[field.DeriveFrom]
	if !ok || source == "" {
		return fmt.Errorf("field %q: derive_from references missing/empty sibling %q", field.Name, field.DeriveFrom)
	}
	line, err := utils.GenerateHtpasswd(field.DeriveUsername, source)
	if err != nil {
		return fmt.Errorf("field %q: %w", field.Name, err)
	}
	data[field.Name] = line
	return nil
}

func deriveClusterSecret(field config.SecretField, data map[string]string, dryRun bool) error {
	if field.DeriveNamespace == "" || field.DeriveSecret == "" || field.DeriveKey == "" {
		return fmt.Errorf("field %q: derive=cluster_secret requires derive_namespace, derive_secret, and derive_key", field.Name)
	}
	if dryRun {
		// No cluster access in dry-run: emit a self-describing placeholder. It
		// still flows into render templates so the dry-run output shows where
		// the live value would land.
		data[field.Name] = fmt.Sprintf("<cluster:%s/%s.%s>",
			field.DeriveNamespace, field.DeriveSecret, field.DeriveKey)
		return nil
	}
	value, err := utils.FetchClusterSecret(field.DeriveNamespace, field.DeriveSecret, field.DeriveKey)
	if err != nil {
		return fmt.Errorf("field %q: %w", field.Name, err)
	}
	data[field.Name] = value
	return nil
}

// deriveRandomKey backs jwt_secret and hmac: a base64-encoded random key. The
// byte length defaults to 32 (256-bit, the usual HMAC/JWT signing-key size) and
// can be overridden with `length`.
func deriveRandomKey(field config.SecretField, data map[string]string) error {
	n := field.Length
	if n == 0 {
		n = 32
	}
	key, err := utils.GenerateBase64Key(n)
	if err != nil {
		return fmt.Errorf("field %q: %w", field.Name, err)
	}
	data[field.Name] = key
	return nil
}

// deriveTLS writes a self-signed cert+key pair into two sibling keys derived
// from the field name: "<name>.crt" and "<name>.key" (matching the
// kubernetes.io/tls convention). The field's own name is left unset so it
// doesn't appear as a redundant third key.
func deriveTLS(field config.SecretField, data map[string]string) error {
	cn := field.DeriveCommonName
	if cn == "" {
		cn = field.Name
	}
	cert, key, err := utils.GenerateSelfSignedTLS(cn, field.DeriveHosts)
	if err != nil {
		return fmt.Errorf("field %q: %w", field.Name, err)
	}
	data[field.Name+".crt"] = cert
	data[field.Name+".key"] = key
	return nil
}

// deriveSSHKeypair writes an ed25519 SSH key pair into two sibling keys: the
// private key under "<name>" and the public key under "<name>.pub".
func deriveSSHKeypair(field config.SecretField, data map[string]string) error {
	priv, pub, err := utils.GenerateSSHKeypair(field.DeriveComment)
	if err != nil {
		return fmt.Errorf("field %q: %w", field.Name, err)
	}
	data[field.Name] = priv
	data[field.Name+".pub"] = pub
	return nil
}

// deriveFile reads the file at derive_path into the field's value. The path is
// resolved relative to the process working directory (callers run kryptos from
// the repo root), matching how config_dir and the output layout are resolved.
func deriveFile(field config.SecretField, data map[string]string) error {
	if field.DerivePath == "" {
		return fmt.Errorf("field %q: derive=file requires derive_path", field.Name)
	}
	contents, err := utils.ReadFileString(field.DerivePath)
	if err != nil {
		return fmt.Errorf("field %q: %w", field.Name, err)
	}
	data[field.Name] = contents
	return nil
}
