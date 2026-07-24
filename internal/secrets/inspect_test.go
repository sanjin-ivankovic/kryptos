package secrets

import (
	"os"
	"path/filepath"
	"testing"

	"source.example.com/example-org/kryptos/internal/config"
)

func TestSealedKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "valkey-auth-sealed-secret.yaml")
	body := `
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: valkey-auth
  namespace: valkey
spec:
  encryptedData:
    password: AgAHRnf...
    extra: AgBxyz...
  template:
    metadata:
      name: valkey-auth
    type: Opaque
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	keys, err := SealedKeys(path)
	if err != nil {
		t.Fatalf("SealedKeys: %v", err)
	}
	if len(keys) != 2 || keys[0] != "extra" || keys[1] != "password" {
		t.Errorf("keys = %v, want [extra password] (sorted)", keys)
	}
}

func TestSealedKeysMissingFile(t *testing.T) {
	if _, err := SealedKeys(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestExpectedKeys(t *testing.T) {
	t.Run("plain fields plus stringData", func(t *testing.T) {
		app := &config.AppConfig{Namespace: "demo"}
		secret := &config.Secret{
			Name:       "demo-secret",
			Fields:     []config.SecretField{{Name: "username"}, {Name: "password", Generator: "secure"}},
			StringData: map[string]string{"host": "db.local"},
		}
		keys, err := ExpectedKeys(app, secret)
		if err != nil {
			t.Fatalf("ExpectedKeys: %v", err)
		}
		if !sameSet(keys, []string{"username", "password", "host"}) {
			t.Errorf("keys = %v, want username/password/host", keys)
		}
	})

	t.Run("drops underscore-internal fields, keeps render output", func(t *testing.T) {
		app := &config.AppConfig{Namespace: "harbor"}
		secret := &config.Secret{
			Name: "cfg",
			Fields: []config.SecretField{
				{Name: "_valkey_password", Derive: "cluster_secret",
					DeriveNamespace: "valkey", DeriveSecret: "valkey-auth", DeriveKey: "password"},
				{Name: "config.yml", Derive: "render", DeriveTemplate: "pw={{ ._valkey_password }}"},
			},
		}
		keys, err := ExpectedKeys(app, secret)
		if err != nil {
			t.Fatalf("ExpectedKeys: %v", err)
		}
		if !sameSet(keys, []string{"config.yml"}) {
			t.Errorf("keys = %v, want only config.yml (underscore field dropped)", keys)
		}
	})

	t.Run("tls expands to .crt and .key", func(t *testing.T) {
		app := &config.AppConfig{Namespace: "demo"}
		secret := &config.Secret{
			Name:   "tls-secret",
			Fields: []config.SecretField{{Name: "tls", Derive: "tls", DeriveCommonName: "x"}},
		}
		keys, err := ExpectedKeys(app, secret)
		if err != nil {
			t.Fatalf("ExpectedKeys: %v", err)
		}
		if !sameSet(keys, []string{"tls.crt", "tls.key"}) {
			t.Errorf("keys = %v, want tls.crt/tls.key", keys)
		}
	})

	t.Run("dockerconfigjson collapses to one key", func(t *testing.T) {
		app := &config.AppConfig{Namespace: "ci"}
		secret := &config.Secret{
			Name:   "dockercfg",
			Type:   "kubernetes.io/dockerconfigjson",
			Fields: []config.SecretField{{Name: "username"}, {Name: "password"}},
		}
		keys, err := ExpectedKeys(app, secret)
		if err != nil {
			t.Fatalf("ExpectedKeys: %v", err)
		}
		if !sameSet(keys, []string{".dockerconfigjson"}) {
			t.Errorf("keys = %v, want .dockerconfigjson", keys)
		}
	})
}

func TestDiffKeys(t *testing.T) {
	missing, orphaned := DiffKeys(
		[]string{"a", "b", "c"}, // expected (config)
		[]string{"b", "c", "d"}, // actual (sealed)
	)
	if !sameSet(missing, []string{"a"}) {
		t.Errorf("missing = %v, want [a]", missing)
	}
	if !sameSet(orphaned, []string{"d"}) {
		t.Errorf("orphaned = %v, want [d]", orphaned)
	}

	// Identical sets → no diff.
	m, o := DiffKeys([]string{"x", "y"}, []string{"y", "x"})
	if len(m) != 0 || len(o) != 0 {
		t.Errorf("identical sets should diff empty, got missing=%v orphaned=%v", m, o)
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]bool, len(a))
	for _, s := range a {
		m[s] = true
	}
	for _, s := range b {
		if !m[s] {
			return false
		}
	}
	return true
}
