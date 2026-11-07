package secrets

import (
	"strings"
	"testing"

	"source.example.com/example-org/kryptos/internal/config"
)

func immutableSecret() *config.Secret {
	return &config.Secret{
		Name: "app-secret",
		Fields: []config.SecretField{
			{Name: "SECRET_KEY", Generator: "apikey", Required: true, Immutable: true},
			{Name: "password", Generator: "secure", Required: true},
		},
	}
}

func sealed(yes bool) ImmutablePolicy {
	return ImmutablePolicy{Sealed: func(*config.Secret) bool { return yes }}
}

func TestImmutableBlocksGeneratingOnASealedSecret(t *testing.T) {
	_, err := NonInteractiveResolver(NewMapSource(nil, nil), sealed(true))(immutableSecret())
	if err == nil || !strings.Contains(err.Error(), "SECRET_KEY") || strings.Contains(err.Error(), "password") {
		t.Fatalf("want an error naming only SECRET_KEY, got: %v", err)
	}
}

func TestImmutableAllowsTheFirstSeal(t *testing.T) {
	if _, err := NonInteractiveResolver(NewMapSource(nil, nil), sealed(false))(immutableSecret()); err != nil {
		t.Fatalf("first seal must generate freely: %v", err)
	}
}

func TestImmutableAcceptsAnExplicitValue(t *testing.T) {
	src := NewMapSource(nil, map[string]string{"SECRET_KEY": "the-current-key"})
	data, err := NonInteractiveResolver(src, sealed(true))(immutableSecret())
	if err != nil {
		t.Fatalf("an explicit value is the caller's choice: %v", err)
	}
	if data["SECRET_KEY"] != "the-current-key" {
		t.Errorf("SECRET_KEY = %q", data["SECRET_KEY"])
	}
}

func TestImmutableAllowFlag(t *testing.T) {
	policy := sealed(true)
	policy.Allow = true
	if _, err := NonInteractiveResolver(NewMapSource(nil, nil), policy)(immutableSecret()); err != nil {
		t.Fatalf("--allow-immutable must let it through: %v", err)
	}
}

func TestImmutableWithoutPolicyIsUnguarded(t *testing.T) {
	if _, err := NonInteractiveResolver(NewMapSource(nil, nil))(immutableSecret()); err != nil {
		t.Fatalf("no policy means no guard: %v", err)
	}
}

func TestRotateImmutableField(t *testing.T) {
	src := NewMapSource(nil, map[string]string{"SECRET_KEY": "kept"})
	// Rotating only the mutable field passes.
	if _, err := RotateResolver(src, []string{"password"}, sealed(true))(immutableSecret()); err != nil {
		t.Fatalf("rotating a mutable field: %v", err)
	}
	// Rotating everything would regenerate the immutable key.
	_, err := RotateResolver(src, nil, sealed(true))(immutableSecret())
	if err == nil || !strings.Contains(err.Error(), "SECRET_KEY") {
		t.Fatalf("want a refusal naming SECRET_KEY, got: %v", err)
	}
}

func TestImmutableDerivedFields(t *testing.T) {
	secret := &config.Secret{
		Name: "s",
		Fields: []config.SecretField{
			{Name: "pw", Generator: "secure", Required: true},
			{Name: "line", Derive: "htpasswd", DeriveFrom: "pw", DeriveUsername: "u", Immutable: true},
			{Name: "url", Derive: "render", DeriveTemplate: "x://{{ .pw }}@h", Immutable: true},
			{Name: "cert", Derive: "tls", Immutable: true},
			{Name: "copy", Derive: "cluster_secret", DeriveNamespace: "n", DeriveSecret: "s", DeriveKey: "k", Immutable: true},
		},
	}
	_, err := NonInteractiveResolver(NewMapSource(nil, nil), sealed(true))(secret)
	if err == nil {
		t.Fatal("want a refusal")
	}
	for _, name := range []string{"line", "url", "cert"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error should name %q: %v", name, err)
		}
	}
	if strings.Contains(err.Error(), "copy") {
		t.Errorf("a cluster_secret copy does not change: %v", err)
	}
}
