package secrets

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"source.example.com/example-org/kryptos/internal/config"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

func TestGenerateFieldValue(t *testing.T) {
	t.Run("secure has the default length and no symbols", func(t *testing.T) {
		got, err := GenerateFieldValue(config.SecretField{Generator: "secure"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 32 {
			t.Errorf("secure default length = %d, want 32", len(got))
		}
		if strings.ContainsAny(got, "!@#$%^&*") {
			t.Errorf("secure should not contain symbols: %q", got)
		}
	})

	t.Run("strong contains a symbol", func(t *testing.T) {
		got, err := GenerateFieldValue(config.SecretField{Generator: "strong"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.ContainsAny(got, "!@#$%^&*") {
			t.Errorf("strong should contain a symbol: %q", got)
		}
	})

	t.Run("apikey default length is 64 hex chars", func(t *testing.T) {
		got, err := GenerateFieldValue(config.SecretField{Generator: "apikey"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 64 {
			t.Errorf("apikey default length = %d, want 64", len(got))
		}
	})

	t.Run("length override is honoured", func(t *testing.T) {
		got, err := GenerateFieldValue(config.SecretField{Generator: "apikey", Length: 32})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 32 {
			t.Errorf("apikey with Length=32 = %d chars", len(got))
		}
	})

	t.Run("no generator returns empty (caller must supply)", func(t *testing.T) {
		got, err := GenerateFieldValue(config.SecretField{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Errorf("expected empty string for no generator, got %q", got)
		}
	})
}

func TestExpandMagicKeyword(t *testing.T) {
	t.Run("expands a bare keyword", func(t *testing.T) {
		got, err := ExpandMagicKeyword("apikey", config.SecretField{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 64 {
			t.Errorf("expanded apikey = %d chars, want 64", len(got))
		}
	})

	t.Run("trims surrounding whitespace before matching", func(t *testing.T) {
		got, err := ExpandMagicKeyword("  secure  ", config.SecretField{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 32 {
			t.Errorf("expanded secure = %d chars, want 32", len(got))
		}
	})

	t.Run("passes a non-keyword value through unchanged", func(t *testing.T) {
		got, err := ExpandMagicKeyword("my-literal-password", config.SecretField{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "my-literal-password" {
			t.Errorf("got %q, want the literal back", got)
		}
	})
}

func TestApplyDerivedFieldsHtpasswd(t *testing.T) {
	t.Run("computes user:bcrypt from a sibling field", func(t *testing.T) {
		secret := &config.Secret{Fields: []config.SecretField{
			{Name: "REGISTRY_PASSWD"},
			{Name: "REGISTRY_HTPASSWD", Derive: "htpasswd",
				DeriveFrom: "REGISTRY_PASSWD", DeriveUsername: "harbor_registry_user"},
		}}
		data := map[string]string{"REGISTRY_PASSWD": "plaintext-pw"}
		if err := ApplyDerivedFields(secret, data, false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		line := data["REGISTRY_HTPASSWD"]
		user, hash, ok := strings.Cut(line, ":")
		if !ok || user != "harbor_registry_user" {
			t.Fatalf("htpasswd line malformed: %q", line)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("plaintext-pw")); err != nil {
			t.Errorf("derived bcrypt does not verify: %v", err)
		}
	})

	t.Run("errors when derive_from is missing", func(t *testing.T) {
		secret := &config.Secret{Fields: []config.SecretField{
			{Name: "h", Derive: "htpasswd", DeriveUsername: "u"},
		}}
		if err := ApplyDerivedFields(secret, map[string]string{}, false); err == nil {
			t.Fatal("expected an error when derive_from is unset")
		}
	})

	t.Run("errors when the sibling is empty", func(t *testing.T) {
		secret := &config.Secret{Fields: []config.SecretField{
			{Name: "pw"},
			{Name: "h", Derive: "htpasswd", DeriveFrom: "pw", DeriveUsername: "u"},
		}}
		if err := ApplyDerivedFields(secret, map[string]string{"pw": ""}, false); err == nil {
			t.Fatal("expected an error when the source sibling is empty")
		}
	})
}

func TestApplyDerivedFieldsClusterSecretDryRun(t *testing.T) {
	secret := &config.Secret{Fields: []config.SecretField{
		{Name: "REDIS_PASSWORD", Derive: "cluster_secret",
			DeriveNamespace: "valkey", DeriveSecret: "valkey-auth", DeriveKey: "password"},
	}}
	data := map[string]string{}
	if err := ApplyDerivedFields(secret, data, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "<cluster:valkey/valkey-auth.password>"
	if data["REDIS_PASSWORD"] != want {
		t.Errorf("dry-run placeholder = %q, want %q", data["REDIS_PASSWORD"], want)
	}
}

func TestApplyDerivedFieldsTwoPassOrdering(t *testing.T) {
	// render (pass 2) must see the outputs of pass-1 derives regardless of
	// declaration order. The render field is declared FIRST here.
	secret := &config.Secret{Fields: []config.SecretField{
		{Name: "config.yml", Derive: "render",
			DeriveTemplate: "redis://:{{ ._valkey_password }}@valkey:6379/1\nauth: {{ .htline }}"},
		{Name: "_valkey_password", Derive: "cluster_secret",
			DeriveNamespace: "valkey", DeriveSecret: "valkey-auth", DeriveKey: "password"},
		{Name: "pw"},
		{Name: "htline", Derive: "htpasswd", DeriveFrom: "pw", DeriveUsername: "u"},
	}}
	data := map[string]string{"pw": "registry-pw"}

	if err := ApplyDerivedFields(secret, data, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rendered := data["config.yml"]
	if !strings.Contains(rendered, "<cluster:valkey/valkey-auth.password>") {
		t.Errorf("render did not see the cluster_secret output:\n%s", rendered)
	}
	if !strings.Contains(rendered, "auth: u:") {
		t.Errorf("render did not see the htpasswd output:\n%s", rendered)
	}
}

func TestApplyDerivedFieldsUnknownType(t *testing.T) {
	secret := &config.Secret{Fields: []config.SecretField{{Name: "x", Derive: "totally-bogus"}}}
	err := ApplyDerivedFields(secret, map[string]string{}, false)
	if err == nil || !strings.Contains(err.Error(), "unknown derive type") {
		t.Fatalf("expected an unknown-derive-type error, got: %v", err)
	}
}

func TestDeriveRandomKey(t *testing.T) {
	for _, dt := range []string{"jwt_secret", "hmac"} {
		t.Run(dt+" default is 32 base64 bytes", func(t *testing.T) {
			secret := &config.Secret{Fields: []config.SecretField{{Name: "key", Derive: dt}}}
			data := map[string]string{}
			if err := ApplyDerivedFields(secret, data, false); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			raw, err := base64.StdEncoding.DecodeString(data["key"])
			if err != nil {
				t.Fatalf("%s value not valid base64: %v", dt, err)
			}
			if len(raw) != 32 {
				t.Errorf("%s decoded to %d bytes, want 32", dt, len(raw))
			}
		})
	}

	t.Run("length override is honoured", func(t *testing.T) {
		secret := &config.Secret{Fields: []config.SecretField{{Name: "k", Derive: "hmac", Length: 64}}}
		data := map[string]string{}
		if err := ApplyDerivedFields(secret, data, false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		raw, _ := base64.StdEncoding.DecodeString(data["k"])
		if len(raw) != 64 {
			t.Errorf("hmac with Length=64 decoded to %d bytes", len(raw))
		}
	})
}

func TestDeriveTLS(t *testing.T) {
	secret := &config.Secret{Fields: []config.SecretField{
		{Name: "tls", Derive: "tls", DeriveCommonName: "example.example.com",
			DeriveHosts: []string{"example.example.com", "127.0.0.1"}},
	}}
	data := map[string]string{}
	if err := ApplyDerivedFields(secret, data, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The field name itself must NOT appear; the .crt/.key siblings must.
	if _, ok := data["tls"]; ok {
		t.Error("tls derive should not set the bare field name")
	}
	certPEM, ok := data["tls.crt"]
	if !ok {
		t.Fatal("expected a tls.crt key")
	}
	if _, ok := data["tls.key"]; !ok {
		t.Fatal("expected a tls.key key")
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("tls.crt is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("tls.crt does not parse: %v", err)
	}
	if cert.Subject.CommonName != "example.example.com" {
		t.Errorf("CN = %q, want example.example.com", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "example.example.com" {
		t.Errorf("DNS SANs = %v, want [example.example.com]", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 {
		t.Errorf("IP SANs = %v, want one IP", cert.IPAddresses)
	}
}

func TestDeriveSSHKeypair(t *testing.T) {
	secret := &config.Secret{Fields: []config.SecretField{
		{Name: "id_ed25519", Derive: "ssh_keypair", DeriveComment: "kryptos@example"},
	}}
	data := map[string]string{}
	if err := ApplyDerivedFields(secret, data, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	priv, ok := data["id_ed25519"]
	if !ok {
		t.Fatal("expected the private key under the field name")
	}
	if _, err := ssh.ParsePrivateKey([]byte(priv)); err != nil {
		t.Errorf("private key does not parse: %v", err)
	}

	pub, ok := data["id_ed25519.pub"]
	if !ok {
		t.Fatal("expected the public key under <name>.pub")
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub)); err != nil {
		t.Errorf("public key is not a valid authorized_keys line: %v", err)
	}
	if !strings.Contains(pub, "kryptos@example") {
		t.Errorf("public key missing the comment: %q", pub)
	}
}

func TestDeriveFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blob.txt")
	if err := os.WriteFile(path, []byte("file-contents\n"), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	t.Run("reads the file into the field", func(t *testing.T) {
		secret := &config.Secret{Fields: []config.SecretField{
			{Name: "blob", Derive: "file", DerivePath: path},
		}}
		data := map[string]string{}
		if err := ApplyDerivedFields(secret, data, false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if data["blob"] != "file-contents\n" {
			t.Errorf("blob = %q, want the file contents", data["blob"])
		}
	})

	t.Run("errors when derive_path is missing", func(t *testing.T) {
		secret := &config.Secret{Fields: []config.SecretField{{Name: "b", Derive: "file"}}}
		if err := ApplyDerivedFields(secret, map[string]string{}, false); err == nil {
			t.Fatal("expected an error when derive_path is unset")
		}
	})

	t.Run("errors when the file does not exist", func(t *testing.T) {
		secret := &config.Secret{Fields: []config.SecretField{
			{Name: "b", Derive: "file", DerivePath: filepath.Join(dir, "nope.txt")},
		}}
		if err := ApplyDerivedFields(secret, map[string]string{}, false); err == nil {
			t.Fatal("expected an error for a missing file")
		}
	})
}
