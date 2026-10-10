package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"source.example.com/example-org/kryptos/internal/config"
)

// addFieldFixture builds a Layout rooted in a temp dir whose OutputLayout
// resolves to <root>/apps/<app>/secrets/<file>, plus the app dir that
// SecretsDir requires to exist. Returns the layout and the sealed file path
// the pipeline will resolve for the secret.
func addFieldFixture(t *testing.T, secret *config.Secret) (*config.Layout, string) {
	t.Helper()
	root := t.TempDir()
	appDir := filepath.Join(root, "apps", "demo")
	if err := os.MkdirAll(filepath.Join(appDir, "secrets"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	layout := &config.Layout{
		RepoRoot:            root,
		ConfigDir:           root,
		OutputLayout:        filepath.Join("apps", "{section}", "{app}", "secrets", "{name}"),
		Sections:            []string{""},
		ControllerNamespace: "kube-system",
	}
	// With an empty section the layout collapses to apps/demo/secrets/<file>.
	path := filepath.Join(appDir, "secrets", config.SealedFilename(secret))
	return layout, path
}

// writeSealed writes a minimal SealedSecret carrying the given keys. The
// ciphertext is synthetic — AddField only ever reads the key set.
func writeSealed(t *testing.T, path string, keys ...string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\n" +
		"metadata:\n  name: demo-secret\n  namespace: demo\nspec:\n  encryptedData:\n")
	for _, k := range keys {
		b.WriteString("    " + k + ": AgSYNTHETIC\n")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func demoApp() *config.AppConfig {
	return &config.AppConfig{AppName: "demo", DisplayName: "Demo", Namespace: "demo"}
}

func demoSecret() *config.Secret {
	return &config.Secret{
		Name:        "demo-secret",
		DisplayName: "Demo Secret",
		Fields: []config.SecretField{
			{Name: "jwks.rsa.key", Generator: "secure"},
			{Name: "headlamp.client.secret", Generator: "secure"},
			{Name: "omni.client.secret", Generator: "secure"},
			{Name: "digest", Derive: "htpasswd", DeriveFrom: "headlamp.client.secret",
				DeriveUsername: "admin"},
		},
	}
}

func TestAddFieldErrors(t *testing.T) {
	t.Run("errors when the sealed file does not exist", func(t *testing.T) {
		secret := demoSecret()
		layout, _ := addFieldFixture(t, secret)
		p := &Pipeline{Layout: layout}

		res := p.AddField(AddFieldRequest{
			App: demoApp(), Secret: secret, Field: "omni.client.secret", Value: "v",
		})
		if res.Err == nil {
			t.Fatal("expected an error when no sealed file exists")
		}
		// The message must point at the command that creates it.
		if !strings.Contains(res.Err.Error(), "kryptos seal") {
			t.Errorf("expected the error to name `kryptos seal`, got: %v", res.Err)
		}
	})

	t.Run("errors on a field the config does not declare", func(t *testing.T) {
		secret := demoSecret()
		layout, path := addFieldFixture(t, secret)
		writeSealed(t, path, "jwks.rsa.key")
		p := &Pipeline{Layout: layout}

		res := p.AddField(AddFieldRequest{
			App: demoApp(), Secret: secret, Field: "typo.secret", Value: "v",
		})
		if res.Err == nil {
			t.Fatal("expected an error for an undeclared field")
		}
		if !strings.Contains(res.Err.Error(), "no field named") {
			t.Errorf("unexpected error: %v", res.Err)
		}
		// The error should list what IS declared, to catch typos.
		if !strings.Contains(res.Err.Error(), "omni.client.secret") {
			t.Errorf("expected declared fields listed, got: %v", res.Err)
		}
	})

	t.Run("errors on a derived field", func(t *testing.T) {
		secret := demoSecret()
		layout, path := addFieldFixture(t, secret)
		writeSealed(t, path, "jwks.rsa.key")
		p := &Pipeline{Layout: layout}

		res := p.AddField(AddFieldRequest{
			App: demoApp(), Secret: secret, Field: "digest", Value: "v",
		})
		if res.Err == nil {
			t.Fatal("expected an error for a derived field")
		}
		if !strings.Contains(res.Err.Error(), "derived") {
			t.Errorf("expected the error to explain the field is derived, got: %v", res.Err)
		}
	})

	t.Run("errors when the key is already sealed", func(t *testing.T) {
		secret := demoSecret()
		layout, path := addFieldFixture(t, secret)
		writeSealed(t, path, "jwks.rsa.key", "headlamp.client.secret")
		p := &Pipeline{Layout: layout}

		res := p.AddField(AddFieldRequest{
			App: demoApp(), Secret: secret, Field: "jwks.rsa.key", Value: "v",
		})
		if res.Err == nil {
			t.Fatal("expected an error when the key is already present")
		}
		// This is the incident guard: re-adding must not silently rotate.
		if !strings.Contains(res.Err.Error(), "rotate") {
			t.Errorf("expected the error to warn about rotation, got: %v", res.Err)
		}
	})

	t.Run("errors on an empty field name", func(t *testing.T) {
		secret := demoSecret()
		layout, path := addFieldFixture(t, secret)
		writeSealed(t, path, "jwks.rsa.key")
		p := &Pipeline{Layout: layout}

		res := p.AddField(AddFieldRequest{App: demoApp(), Secret: secret, Value: "v"})
		if res.Err == nil {
			t.Fatal("expected an error for an empty field name")
		}
	})
}

func TestAddFieldDryRun(t *testing.T) {
	secret := demoSecret()
	layout, path := addFieldFixture(t, secret)
	writeSealed(t, path, "jwks.rsa.key")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var emitted map[string]string
	p := &Pipeline{Layout: layout, DryRun: true, Hooks: Hooks{
		EmitDryRun: func(_ *config.AppConfig, _ *config.Secret, data map[string]string) {
			emitted = data
		},
	}}

	// Sealer is nil: a dry run must not reach it.
	res := p.AddField(AddFieldRequest{
		App: demoApp(), Secret: secret, Field: "omni.client.secret", Value: "new-value",
	})
	if res.Err != nil {
		t.Fatalf("dry-run AddField: %v", res.Err)
	}
	if res.OutputPath != "(dry-run)" {
		t.Errorf("OutputPath = %q, want (dry-run)", res.OutputPath)
	}
	if emitted["omni.client.secret"] != "new-value" {
		t.Errorf("expected the field previewed, got: %v", emitted)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(before) != string(after) {
		t.Error("dry-run must not modify the sealed file")
	}
}

func TestAddFieldAllowsOverwriteWithForce(t *testing.T) {
	secret := demoSecret()
	layout, path := addFieldFixture(t, secret)
	writeSealed(t, path, "jwks.rsa.key")

	// Overwrite bypasses the duplicate-key guard. Sealer is nil and DryRun is
	// set so the call stops before shelling out; reaching the dry-run branch
	// proves the guard did not fire.
	p := &Pipeline{Layout: layout, DryRun: true}
	res := p.AddField(AddFieldRequest{
		App: demoApp(), Secret: secret, Field: "jwks.rsa.key", Value: "v", Overwrite: true,
	})
	if res.Err != nil {
		t.Fatalf("expected --force to permit re-adding a sealed key, got: %v", res.Err)
	}
}

func TestResealImpact(t *testing.T) {
	secret := demoSecret()
	// A non-generator field keeps its value across a re-seal.
	secret.Fields = append(secret.Fields, config.SecretField{Name: "issuer.url"})

	_, path := addFieldFixture(t, secret)
	writeSealed(t, path, "jwks.rsa.key", "headlamp.client.secret", "issuer.url", "digest")

	w, err := ResealImpact(demoApp(), secret, path)
	if err != nil {
		t.Fatalf("ResealImpact: %v", err)
	}

	wantRegen := map[string]bool{
		"jwks.rsa.key":           true,
		"headlamp.client.secret": true,
		// derived from a rotating generator field, so it rotates too
		"digest": true,
	}
	if len(w.Regenerated) != len(wantRegen) {
		t.Fatalf("Regenerated = %v, want keys %v", w.Regenerated, wantRegen)
	}
	for _, k := range w.Regenerated {
		if !wantRegen[k] {
			t.Errorf("unexpected regenerated key %q (got %v)", k, w.Regenerated)
		}
	}

	if len(w.Preserved) != 1 || w.Preserved[0] != "issuer.url" {
		t.Errorf("Preserved = %v, want [issuer.url]", w.Preserved)
	}
}
