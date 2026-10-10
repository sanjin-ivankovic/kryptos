package cmd

import (
	"testing"

	"source.example.com/example-org/kryptos/internal/config"
)

// Field names in real configs routinely contain dots (e.g. "omni.client.secret"
// in an OIDC secret). The shared qualifiedOrBare helper treats ANY dotted --set
// key as "secret.field", so without an exact-match source a bare
// `--set omni.client.secret=v` is filed under a secret named "omni", never
// matches, and a generator field silently mints a random value instead — the
// user's explicit value is discarded without warning.
func TestBuildAddValueSourceHandlesDottedFieldNames(t *testing.T) {
	const (
		secretName = "authelia-oidc-secret"
		fieldName  = "omni.client.secret"
	)

	tests := []struct {
		name    string
		setFlag string
	}{
		{"bare field name", fieldName + "=SENTINEL"},
		{"qualified secret.field", secretName + "." + fieldName + "=SENTINEL"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src, err := buildAddValueSource("", []string{tc.setFlag}, secretName, fieldName)
			if err != nil {
				t.Fatalf("buildAddValueSource: %v", err)
			}
			got, ok := src.Lookup(secretName, fieldName)
			if !ok {
				t.Fatalf("value for %q not found; the explicit --set was dropped", fieldName)
			}
			if got != "SENTINEL" {
				t.Errorf("value = %q, want SENTINEL", got)
			}
		})
	}
}

// An explicit value must win over a generator, otherwise `add` would seal a
// random value while appearing to honour --set.
func TestResolveSingleValuePrefersExplicitOverGenerator(t *testing.T) {
	secret := &config.Secret{
		Name: "demo-secret",
		Fields: []config.SecretField{
			{Name: "omni.client.secret", Generator: "secure"},
		},
	}

	src, err := buildAddValueSource("", []string{"omni.client.secret=EXPLICIT"},
		secret.Name, "omni.client.secret")
	if err != nil {
		t.Fatalf("buildAddValueSource: %v", err)
	}

	got, err := resolveSingleValue(src, secret, "omni.client.secret")
	if err != nil {
		t.Fatalf("resolveSingleValue: %v", err)
	}
	if got != "EXPLICIT" {
		t.Errorf("value = %q, want EXPLICIT (a generator value would be random)", got)
	}
}

// With no explicit value, a generator field must still auto-fill.
func TestResolveSingleValueFallsBackToGenerator(t *testing.T) {
	secret := &config.Secret{
		Name: "demo-secret",
		Fields: []config.SecretField{
			{Name: "token", Generator: "secure"},
		},
	}

	src, err := buildAddValueSource("", nil, secret.Name, "token")
	if err != nil {
		t.Fatalf("buildAddValueSource: %v", err)
	}

	got, err := resolveSingleValue(src, secret, "token")
	if err != nil {
		t.Fatalf("resolveSingleValue: %v", err)
	}
	if got == "" {
		t.Error("expected the generator to supply a value")
	}
}

// A field with no value, generator, or default must fail loudly rather than
// seal an empty string.
func TestResolveSingleValueErrorsWithNoSource(t *testing.T) {
	secret := &config.Secret{
		Name:   "demo-secret",
		Fields: []config.SecretField{{Name: "manual", Required: true}},
	}

	src, err := buildAddValueSource("", nil, secret.Name, "manual")
	if err != nil {
		t.Fatalf("buildAddValueSource: %v", err)
	}

	if _, err := resolveSingleValue(src, secret, "manual"); err == nil {
		t.Error("expected an error when no value source supplies the field")
	}
}
