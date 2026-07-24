package generator

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"source.example.com/example-org/kryptos/internal/config"

	"github.com/goccy/go-yaml"
)

// unmarshalSecret round-trips the generated YAML back into a K8sSecret so tests
// assert on structure, not on byte-for-byte string matching.
func unmarshalSecret(t *testing.T, raw []byte) K8sSecret {
	t.Helper()
	var s K8sSecret
	if err := yaml.Unmarshal(raw, &s); err != nil {
		t.Fatalf("generated YAML did not round-trip: %v\n---\n%s", err, raw)
	}
	return s
}

func TestGenerateRawSecret(t *testing.T) {
	t.Run("defaults type to Opaque", func(t *testing.T) {
		cfg := &config.AppConfig{Namespace: "demo"}
		secret := config.Secret{Name: "demo-secret"}
		raw, err := GenerateRawSecret(cfg, secret, map[string]string{"password": "x"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got := unmarshalSecret(t, raw)
		if got.Type != "Opaque" {
			t.Errorf("type = %q, want Opaque", got.Type)
		}
		if got.APIVersion != "v1" || got.Kind != "Secret" {
			t.Errorf("apiVersion/kind = %q/%q, want v1/Secret", got.APIVersion, got.Kind)
		}
		if got.Metadata.Namespace != "demo" {
			t.Errorf("namespace = %q, want demo", got.Metadata.Namespace)
		}
	})

	t.Run("passes a custom type through", func(t *testing.T) {
		cfg := &config.AppConfig{Namespace: "demo"}
		secret := config.Secret{Name: "tls-secret", Type: "kubernetes.io/tls"}
		raw, err := GenerateRawSecret(cfg, secret, map[string]string{"tls.crt": "c", "tls.key": "k"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := unmarshalSecret(t, raw); got.Type != "kubernetes.io/tls" {
			t.Errorf("type = %q, want kubernetes.io/tls", got.Type)
		}
	})

	t.Run("drops underscore-prefixed internal fields", func(t *testing.T) {
		cfg := &config.AppConfig{Namespace: "demo"}
		secret := config.Secret{Name: "demo-secret"}
		data := map[string]string{
			"config.yml":      "rendered",
			"_valkey_password": "should-not-appear",
		}
		raw, err := GenerateRawSecret(cfg, secret, data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got := unmarshalSecret(t, raw)
		if _, leaked := got.StringData["_valkey_password"]; leaked {
			t.Error("internal field _valkey_password leaked into the secret")
		}
		if got.StringData["config.yml"] != "rendered" {
			t.Errorf("config.yml = %q, want rendered", got.StringData["config.yml"])
		}
	})

	t.Run("errors when a required key is absent", func(t *testing.T) {
		cfg := &config.AppConfig{Namespace: "demo"}
		secret := config.Secret{
			Name:   "demo-secret",
			Fields: []config.SecretField{{Name: "password", Required: true}},
		}
		_, err := GenerateRawSecret(cfg, secret, map[string]string{})
		if err == nil {
			t.Fatal("expected an error for a missing required key")
		}
	})

	t.Run("required key satisfied by static stringData", func(t *testing.T) {
		// A required field can be supplied by the secret's static StringData
		// instead of the runtime data map.
		cfg := &config.AppConfig{Namespace: "demo"}
		secret := config.Secret{
			Name:       "demo-secret",
			Fields:     []config.SecretField{{Name: "host", Required: true}},
			StringData: map[string]string{"host": "db.local"},
		}
		raw, err := GenerateRawSecret(cfg, secret, map[string]string{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := unmarshalSecret(t, raw); got.StringData["host"] != "db.local" {
			t.Errorf("host = %q, want db.local", got.StringData["host"])
		}
	})

	t.Run("static stringData overwrites runtime data for a shared key", func(t *testing.T) {
		// NOTE: precedence here is the OPPOSITE of the interactive workflow.
		// processSecret merges static StringData into `data` only-if-absent
		// BEFORE calling GenerateRawSecret, so the user value wins end-to-end.
		// But GenerateRawSecret's own static-merge loop overwrites
		// unconditionally, so a key present in BOTH the runtime data passed
		// directly here AND secret.StringData resolves to the static value.
		// Characterized so a future refactor that changes this is visible.
		cfg := &config.AppConfig{Namespace: "demo"}
		secret := config.Secret{
			Name:       "demo-secret",
			StringData: map[string]string{"shared": "from-config"},
		}
		raw, err := GenerateRawSecret(cfg, secret, map[string]string{"shared": "from-user"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := unmarshalSecret(t, raw); got.StringData["shared"] != "from-config" {
			t.Errorf("shared = %q, want from-config (static overwrites in GenerateRawSecret)", got.StringData["shared"])
		}
	})
}

func TestGenerateDockerConfigJSON(t *testing.T) {
	t.Run("requires username", func(t *testing.T) {
		if _, err := generateDockerConfigJSON(map[string]string{"password": "p"}); err == nil {
			t.Fatal("expected error for missing username")
		}
	})

	t.Run("requires password", func(t *testing.T) {
		if _, err := generateDockerConfigJSON(map[string]string{"username": "u"}); err == nil {
			t.Fatal("expected error for missing password")
		}
	})

	t.Run("defaults the server to Docker Hub", func(t *testing.T) {
		out, err := generateDockerConfigJSON(map[string]string{"username": "u", "password": "p"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var dcj dockerConfigJSON
		if err := json.Unmarshal([]byte(out), &dcj); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}
		if _, ok := dcj.Auths["https://index.docker.io/v1/"]; !ok {
			t.Errorf("expected the default Docker Hub server key, got auths: %v", dcj.Auths)
		}
	})

	t.Run("auth field is base64(user:pass)", func(t *testing.T) {
		out, err := generateDockerConfigJSON(map[string]string{
			"username": "robot", "password": "tok", "server": "registry.example.com",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var dcj dockerConfigJSON
		if err := json.Unmarshal([]byte(out), &dcj); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}
		entry, ok := dcj.Auths["registry.example.com"]
		if !ok {
			t.Fatalf("custom server key missing; auths: %v", dcj.Auths)
		}
		want := base64.StdEncoding.EncodeToString([]byte("robot:tok"))
		if entry.Auth != want {
			t.Errorf("auth = %q, want %q", entry.Auth, want)
		}
		if entry.Username != "robot" || entry.Password != "tok" {
			t.Errorf("username/password = %q/%q, want robot/tok", entry.Username, entry.Password)
		}
	})
}

func TestGenerateRawSecretDockerConfigJSON(t *testing.T) {
	// The dockerconfigjson type rewrites StringData to a single
	// .dockerconfigjson key regardless of the raw fields supplied.
	cfg := &config.AppConfig{Namespace: "ci"}
	secret := config.Secret{Name: "harbor-dockerconfig", Type: "kubernetes.io/dockerconfigjson"}
	raw, err := GenerateRawSecret(cfg, secret, map[string]string{"username": "u", "password": "p"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := unmarshalSecret(t, raw)
	if len(got.StringData) != 1 {
		t.Errorf("expected exactly one stringData key, got %d: %v", len(got.StringData), got.StringData)
	}
	if _, ok := got.StringData[".dockerconfigjson"]; !ok {
		t.Errorf("expected a .dockerconfigjson key, got: %v", got.StringData)
	}
}
