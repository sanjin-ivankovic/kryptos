package config

import (
	"strings"
	"testing"
)

// validApp is a minimal AppConfig that exercises every derive type correctly;
// Validate must return no errors for it.
func validApp() *AppConfig {
	return &AppConfig{
		AppName:   "demo",
		Namespace: "demo",
		Secrets: []Secret{
			{
				Name: "demo-secret",
				Type: "Opaque",
				Fields: []SecretField{
					{Name: "password", Generator: "secure", Required: true},
					{Name: "htline", Derive: "htpasswd", DeriveFrom: "password", DeriveUsername: "u"},
					{Name: "redis", Derive: "cluster_secret",
						DeriveNamespace: "valkey", DeriveSecret: "valkey-auth", DeriveKey: "password"},
					{Name: "config", Derive: "render",
						DeriveTemplate: "pw={{ .password }} auth={{ .htline }}"},
				},
			},
		},
	}
}

func TestValidateAcceptsAGoodConfig(t *testing.T) {
	if errs := Validate(validApp()); len(errs) != 0 {
		t.Fatalf("expected a valid config to pass, got: %v", errs)
	}
}

// hasErrContaining asserts at least one error mentions substr.
func hasErrContaining(errs []error, substr string) bool {
	for _, e := range errs {
		if strings.Contains(e.Error(), substr) {
			return true
		}
	}
	return false
}

func TestValidateCollectsAllProblems(t *testing.T) {
	// A config riddled with distinct problems; Validate must report ALL of
	// them in one pass, not stop at the first.
	app := &AppConfig{
		AppName:   "", // empty app name
		Namespace: "", // empty namespace
		Secrets: []Secret{
			{
				Name: "Bad_Name", // not DNS-1123
				Type: "Weird",    // unsupported type
				Fields: []SecretField{
					{Name: "f1", Generator: "bogus"},       // unknown generator
					{Name: "f1"},                           // duplicate field name
					{Name: "f2", Default: "@secrue"},       // typo'd magic keyword
					{Name: "d1", Derive: "nope"},           // unknown derive type
					{Name: "d2", Derive: "htpasswd"},       // missing derive_from + derive_username
					{Name: "d3", Derive: "cluster_secret"}, // missing all derive_* fields
					{Name: "d4", Derive: "render", // template ref to a non-field
						DeriveTemplate: "{{ .ghost }}"},
				},
			},
			{Name: "Bad_Name"}, // duplicate secret name (also not DNS-1123, no fields)
		},
	}

	errs := Validate(app)

	wants := []string{
		"app name",                       // empty app name
		"metadata.namespace",             // empty namespace
		"not a valid DNS-1123",           // Bad_Name
		"unsupported type",               // Weird
		"unknown generator",              // bogus
		"duplicate field name",           // f1 twice
		"looks like a magic keyword",     // @secrue
		"unknown derive type",            // nope
		"derive=htpasswd requires",       // d2
		"derive=cluster_secret requires", // d3
		"not a field in this secret",     // d4 ghost
		"duplicate secret name",          // Bad_Name twice
	}
	for _, w := range wants {
		if !hasErrContaining(errs, w) {
			t.Errorf("expected an error containing %q; got %d errors:\n%v", w, len(errs), errs)
		}
	}
}

func TestValidateHtpasswdDeriveFromMustBeAField(t *testing.T) {
	app := &AppConfig{
		AppName: "a", Namespace: "a",
		Secrets: []Secret{{
			Name: "a-secret",
			Fields: []SecretField{
				// derive_from points at a field that doesn't exist.
				{Name: "h", Derive: "htpasswd", DeriveFrom: "ghost", DeriveUsername: "u"},
			},
		}},
	}
	if errs := Validate(app); !hasErrContaining(errs, "not a field in this secret") {
		t.Errorf("expected a dangling derive_from error, got: %v", errs)
	}
}

func TestValidateRenderTemplateParseError(t *testing.T) {
	app := &AppConfig{
		AppName: "a", Namespace: "a",
		Secrets: []Secret{{
			Name: "a-secret",
			Fields: []SecretField{
				{Name: "x", Derive: "render", DeriveTemplate: "{{ .unterminated"},
			},
		}},
	}
	if errs := Validate(app); !hasErrContaining(errs, "does not parse") {
		t.Errorf("expected a template parse error, got: %v", errs)
	}
}

func TestValidateRenderResolvesForwardReference(t *testing.T) {
	// A render template may reference a field declared AFTER it (the two-pass
	// derive runner resolves it). Validate must not flag that as missing.
	app := &AppConfig{
		AppName: "a", Namespace: "a",
		Secrets: []Secret{{
			Name: "a-secret",
			Fields: []SecretField{
				{Name: "cfg", Derive: "render", DeriveTemplate: "{{ .later }}"},
				{Name: "later", Generator: "secure"},
			},
		}},
	}
	if errs := Validate(app); len(errs) != 0 {
		t.Errorf("forward reference should resolve, got: %v", errs)
	}
}

func TestValidateNewDeriveTypes(t *testing.T) {
	t.Run("file requires derive_path", func(t *testing.T) {
		app := &AppConfig{
			AppName: "a", Namespace: "a",
			Secrets: []Secret{{Name: "a-secret", Fields: []SecretField{
				{Name: "f", Derive: "file"},
			}}},
		}
		if errs := Validate(app); !hasErrContaining(errs, "derive=file requires derive_path") {
			t.Errorf("expected a derive_path error, got: %v", errs)
		}
	})

	t.Run("jwt_secret/hmac/tls/ssh_keypair need no extra fields", func(t *testing.T) {
		app := &AppConfig{
			AppName: "a", Namespace: "a",
			Secrets: []Secret{{Name: "a-secret", Fields: []SecretField{
				{Name: "jwt", Derive: "jwt_secret"},
				{Name: "mac", Derive: "hmac"},
				{Name: "cert", Derive: "tls"},
				{Name: "key", Derive: "ssh_keypair"},
				{Name: "blob", Derive: "file", DerivePath: "x"},
			}}},
		}
		if errs := Validate(app); len(errs) != 0 {
			t.Errorf("expected the new derive types to validate cleanly, got: %v", errs)
		}
	})
}

func TestValidateDockerConfigJSONRequiresUserPass(t *testing.T) {
	app := &AppConfig{
		AppName: "ci", Namespace: "ci",
		Secrets: []Secret{{
			Name:   "dockercfg",
			Type:   "kubernetes.io/dockerconfigjson",
			Fields: []SecretField{{Name: "username"}}, // password missing
		}},
	}
	if errs := Validate(app); !hasErrContaining(errs, "missing a username and/or password") {
		t.Errorf("expected a dockerconfigjson user/pass error, got: %v", errs)
	}
}

func TestValidateAcceptsDockerConfigJSONWithUserPass(t *testing.T) {
	app := &AppConfig{
		AppName: "ci", Namespace: "ci",
		Secrets: []Secret{{
			Name: "dockercfg",
			Type: "kubernetes.io/dockerconfigjson",
			Fields: []SecretField{
				{Name: "username", Required: true},
				{Name: "password", Required: true},
			},
		}},
	}
	if errs := Validate(app); len(errs) != 0 {
		t.Errorf("a complete dockerconfigjson secret should pass, got: %v", errs)
	}
}

func TestTemplateFieldRefs(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"single ref", "{{ .password }}", []string{"password"}},
		{"multiple refs", "{{ .a }}-{{ .b }}", []string{"a", "b"}},
		{"dedups repeated refs", "{{ .x }}{{ .x }}", []string{"x"}},
		{"ref inside an if", "{{ if .flag }}{{ .val }}{{ end }}", []string{"flag", "val"}},
		{"no refs", "plain text", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := templateFieldRefs(tc.body)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !sameStringSet(got, tc.want) {
				t.Errorf("templateFieldRefs(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]bool, len(a))
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		if !set[s] {
			return false
		}
	}
	return true
}
