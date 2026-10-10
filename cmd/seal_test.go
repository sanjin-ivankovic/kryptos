package cmd

import "testing"

// TestQualifiedOrBare_DottedFieldNames guards the silent-substitution bug that
// motivated `kryptos add`: secret FIELD names commonly contain dots
// ("jwks.rsa.key"). If a dotted --set key is treated purely as
// "secret.field", the value is filed under a non-existent secret, never
// matches, and a generator field quietly produces a random value instead —
// which is how a live RSA signing key gets rotated by accident.
func TestQualifiedOrBare_DottedFieldNames(t *testing.T) {
	src := qualifiedOrBare(map[string]string{
		"jwks.rsa.key":                    "KEY",
		"authelia-oidc-secret.omni.token": "QUALIFIED",
		"plain":                           "BARE",
	})

	// A dotted FIELD name must resolve for any secret.
	if got, ok := src.Lookup("authelia-oidc-secret", "jwks.rsa.key"); !ok || got != "KEY" {
		t.Errorf("dotted field name: got (%q,%v), want (\"KEY\",true)", got, ok)
	}
	// A genuine secret.field qualifier still wins for its own secret.
	if got, ok := src.Lookup("authelia-oidc-secret", "omni.token"); !ok || got != "QUALIFIED" {
		t.Errorf("qualified key: got (%q,%v), want (\"QUALIFIED\",true)", got, ok)
	}
	// Bare keys keep working.
	if got, ok := src.Lookup("any-secret", "plain"); !ok || got != "BARE" {
		t.Errorf("bare key: got (%q,%v), want (\"BARE\",true)", got, ok)
	}
	// Unknown fields still miss.
	if _, ok := src.Lookup("any-secret", "nope"); ok {
		t.Error("unknown field: got a hit, want miss")
	}
}
