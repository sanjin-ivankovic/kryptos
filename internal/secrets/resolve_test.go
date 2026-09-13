package secrets

import (
	"strings"
	"testing"

	"source.example.com/example-org/kryptos/internal/config"
)

func TestNonInteractiveResolverPrecedence(t *testing.T) {
	secret := &config.Secret{
		Name: "demo-secret",
		Fields: []config.SecretField{
			{Name: "explicit", Required: true},
			{Name: "generated", Generator: "apikey", Required: true},
			{Name: "defaulted", Default: "the-default", Required: true},
		},
	}
	// explicit value supplied; generator + default fields fall through.
	src := NewMapSource(map[string]string{"demo-secret.explicit": "from-flag"}, nil)
	data, err := NonInteractiveResolver(src)(secret)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if data["explicit"] != "from-flag" {
		t.Errorf("explicit = %q, want from-flag", data["explicit"])
	}
	if len(data["generated"]) != 64 {
		t.Errorf("generated should be a 64-char apikey, got %d chars", len(data["generated"]))
	}
	if data["defaulted"] != "the-default" {
		t.Errorf("defaulted = %q, want the-default", data["defaulted"])
	}
}

func TestNonInteractiveResolverExplicitBeatsGenerator(t *testing.T) {
	// A field with a generator still takes an explicit value when provided.
	secret := &config.Secret{
		Name:   "s",
		Fields: []config.SecretField{{Name: "password", Generator: "secure", Required: true}},
	}
	src := NewMapSource(nil, map[string]string{"password": "explicit-pw"})
	data, err := NonInteractiveResolver(src)(secret)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if data["password"] != "explicit-pw" {
		t.Errorf("explicit value should beat the generator, got %q", data["password"])
	}
}

func TestNonInteractiveResolverExpandsMagicKeyword(t *testing.T) {
	secret := &config.Secret{
		Name:   "s",
		Fields: []config.SecretField{{Name: "token", Required: true}},
	}
	src := NewMapSource(nil, map[string]string{"token": "apikey"})
	data, err := NonInteractiveResolver(src)(secret)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(data["token"]) != 64 {
		t.Errorf("magic keyword 'apikey' should expand to 64 chars, got %d", len(data["token"]))
	}
}

func TestNonInteractiveResolverRequiredMissingErrors(t *testing.T) {
	secret := &config.Secret{
		Name: "s",
		Fields: []config.SecretField{
			{Name: "needed", Required: true}, // no value, no generator, no default
		},
	}
	_, err := NonInteractiveResolver(NewMapSource(nil, nil))(secret)
	if err == nil {
		t.Fatal("expected a hard error for a required field with no value")
	}
	if !strings.Contains(err.Error(), "needed") {
		t.Errorf("error should name the missing field, got: %v", err)
	}
}

func TestNonInteractiveResolverRequiredSatisfiedByStringData(t *testing.T) {
	// A required field with no input is OK if static stringData provides it.
	secret := &config.Secret{
		Name:       "s",
		Fields:     []config.SecretField{{Name: "host", Required: true}},
		StringData: map[string]string{"host": "db.local"},
	}
	data, err := NonInteractiveResolver(NewMapSource(nil, nil))(secret)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// The resolver leaves it to GenerateRawSecret to merge stringData; it must
	// NOT error and must not invent a value.
	if _, present := data["host"]; present {
		t.Errorf("resolver should not set a stringData-backed field, got %q", data["host"])
	}
}

func TestNonInteractiveResolverOptionalEmpty(t *testing.T) {
	secret := &config.Secret{
		Name:   "s",
		Fields: []config.SecretField{{Name: "optional"}}, // not required, no value
	}
	data, err := NonInteractiveResolver(NewMapSource(nil, nil))(secret)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if v, ok := data["optional"]; !ok || v != "" {
		t.Errorf("optional field should resolve to empty, got %q (present=%v)", v, ok)
	}
}

func TestNonInteractiveResolverSkipsDerivedFields(t *testing.T) {
	secret := &config.Secret{
		Name: "s",
		Fields: []config.SecretField{
			{Name: "pw", Generator: "secure", Required: true},
			{Name: "ht", Derive: "htpasswd", DeriveFrom: "pw", DeriveUsername: "u"},
		},
	}
	data, err := NonInteractiveResolver(NewMapSource(nil, nil))(secret)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, ok := data["ht"]; ok {
		t.Error("resolver must not populate derived fields (the pipeline does)")
	}
}

func TestMapSourceQualifiedBeatsBare(t *testing.T) {
	src := NewMapSource(
		map[string]string{"s.f": "qualified"},
		map[string]string{"f": "bare"},
	)
	if v, _ := src.Lookup("s", "f"); v != "qualified" {
		t.Errorf("qualified should win, got %q", v)
	}
	// A different secret falls back to the bare entry.
	if v, _ := src.Lookup("other", "f"); v != "bare" {
		t.Errorf("bare fallback expected, got %q", v)
	}
}

func TestEnvSource(t *testing.T) {
	env := map[string]string{
		"KRYPTOS_DEMO_SECRET_PASSWORD": "qualified-env",
		"KRYPTOS_TOKEN":                "bare-env",
	}
	src := EnvSource{Getenv: func(k string) string { return env[k] }}

	if v, ok := src.Lookup("demo-secret", "password"); !ok || v != "qualified-env" {
		t.Errorf("qualified env lookup = %q (ok=%v), want qualified-env", v, ok)
	}
	if v, ok := src.Lookup("anything", "token"); !ok || v != "bare-env" {
		t.Errorf("bare env lookup = %q (ok=%v), want bare-env", v, ok)
	}
	if _, ok := src.Lookup("x", "absent"); ok {
		t.Error("absent key should not be found")
	}
}

func TestRotateResolverRegeneratesAllGenerators(t *testing.T) {
	secret := &config.Secret{
		Name: "s",
		Fields: []config.SecretField{
			{Name: "a", Generator: "secure", Required: true},
			{Name: "b", Generator: "apikey", Required: true},
		},
	}
	resolve := RotateResolver(NewMapSource(nil, nil), nil)
	first, err := resolve(secret)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	second, err := resolve(secret)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Fresh values each call (rotation), correct lengths.
	if first["a"] == second["a"] || first["b"] == second["b"] {
		t.Error("rotate should produce fresh values each run")
	}
	if len(first["a"]) != 32 || len(first["b"]) != 64 {
		t.Errorf("unexpected lengths: a=%d b=%d", len(first["a"]), len(first["b"]))
	}
}

func TestRotateResolverTargetsOneField(t *testing.T) {
	secret := &config.Secret{
		Name: "s",
		Fields: []config.SecretField{
			{Name: "rotate_me", Generator: "secure", Required: true},
			{Name: "keep_me", Generator: "apikey", Required: true},
		},
	}
	// Only rotate "rotate_me"; "keep_me" must be supplied (can't read sealed).
	src := NewMapSource(nil, map[string]string{"keep_me": "supplied-value"})
	data, err := RotateResolver(src, []string{"rotate_me"})(secret)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(data["rotate_me"]) != 32 {
		t.Errorf("rotate_me should be regenerated, got %q", data["rotate_me"])
	}
	if data["keep_me"] != "supplied-value" {
		t.Errorf("keep_me should use the supplied value, got %q", data["keep_me"])
	}
}

func TestRotateResolverTargetedFieldNeedsGenerator(t *testing.T) {
	secret := &config.Secret{
		Name:   "s",
		Fields: []config.SecretField{{Name: "plain", Required: true}}, // no generator
	}
	_, err := RotateResolver(NewMapSource(nil, nil), []string{"plain"})(secret)
	if err == nil || !strings.Contains(err.Error(), "no generator") {
		t.Fatalf("expected a no-generator error, got: %v", err)
	}
}

func TestRotateResolverUnknownTargetField(t *testing.T) {
	secret := &config.Secret{
		Name:   "s",
		Fields: []config.SecretField{{Name: "real", Generator: "secure"}},
	}
	_, err := RotateResolver(NewMapSource(nil, nil), []string{"ghost"})(secret)
	if err == nil || !strings.Contains(err.Error(), "no field") {
		t.Fatalf("expected a no-such-field error, got: %v", err)
	}
}

func TestRotateResolverNonRotatedRequiredMissing(t *testing.T) {
	// Targeting one field; another required field has no value/default → error.
	secret := &config.Secret{
		Name: "s",
		Fields: []config.SecretField{
			{Name: "rot", Generator: "secure"},
			{Name: "need", Required: true}, // not rotated, no value
		},
	}
	_, err := RotateResolver(NewMapSource(nil, nil), []string{"rot"})(secret)
	if err == nil || !strings.Contains(err.Error(), "need") {
		t.Fatalf("expected a missing-value error naming 'need', got: %v", err)
	}
}

func TestChainSourceOrder(t *testing.T) {
	first := NewMapSource(nil, map[string]string{"f": "first"})
	second := NewMapSource(nil, map[string]string{"f": "second", "only2": "two"})
	chain := ChainSource{first, second}

	if v, _ := chain.Lookup("s", "f"); v != "first" {
		t.Errorf("earlier source should win, got %q", v)
	}
	if v, _ := chain.Lookup("s", "only2"); v != "two" {
		t.Errorf("later source should still resolve unique keys, got %q", v)
	}
}
