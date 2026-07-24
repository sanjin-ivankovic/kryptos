package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeConfig drops a config file into a temp dir and returns its path.
func writeConfig(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing fixture %s: %v", name, err)
	}
	return path
}

// findSecret returns the named secret from an AppConfig, failing if absent.
func findSecret(t *testing.T, app *AppConfig, name string) Secret {
	t.Helper()
	for _, s := range app.Secrets {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("secret %q not found in app %q", name, app.AppName)
	return Secret{}
}

// findField returns the named field from a Secret, failing if absent.
func findField(t *testing.T, s Secret, name string) SecretField {
	t.Helper()
	for _, f := range s.Fields {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("field %q not found in secret %q", name, s.Name)
	return SecretField{}
}

const v1WithDerives = `
apiVersion: kryptos.dev/v1
kind: SecretConfig
metadata:
  name: harbor
  displayName: Harbor
  namespace: harbor
spec:
  secrets:
    - name: harbor-registry-htpasswd
      displayName: Harbor Registry Credentials
      description: htpasswd derive
      type: Opaque
      fields:
        - name: REGISTRY_PASSWD
          prompt: Registry password
          generator: secure
          required: true
        - name: REGISTRY_HTPASSWD
          derive: htpasswd
          derive_from: REGISTRY_PASSWD
          derive_username: harbor_registry_user
          required: true
    - name: harbor-db-secret
      displayName: Harbor DB
      type: Opaque
      fields:
        - name: username
          default: harbor
          required: true
          sensitive: false
        - name: password
          derive: cluster_secret
          derive_namespace: postgresql
          derive_secret: harbor-db-secret
          derive_key: password
          required: true
`

const legacyConfig = `
app_name: legacyapp
display_name: Legacy App
namespace: legacyns
secrets:
  - name: legacyapp-secret
    display_name: Legacy Secret
    type: Opaque
    description: old-style keys list
    keys:
      - username
      - password
`

const dockerConfigJSONConfig = `
apiVersion: kryptos.dev/v1
kind: SecretConfig
metadata:
  name: ci
  displayName: CI
  namespace: ci
spec:
  secrets:
    - name: harbor-dockerconfig
      displayName: Harbor robot dockerconfig
      type: kubernetes.io/dockerconfigjson
      fields:
        - name: username
          prompt: Username
          required: true
        - name: password
          prompt: Password
          required: true
`

func TestLoadConfigV1WithDerives(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "harbor.yaml", v1WithDerives)

	app, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if app.AppName != "harbor" || app.DisplayName != "Harbor" || app.Namespace != "harbor" {
		t.Errorf("metadata mapping wrong: %+v", app)
	}
	if len(app.Secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(app.Secrets))
	}

	htpasswd := findSecret(t, app, "harbor-registry-htpasswd")
	derived := findField(t, htpasswd, "REGISTRY_HTPASSWD")
	if derived.Derive != "htpasswd" {
		t.Errorf("derive = %q, want htpasswd", derived.Derive)
	}
	if derived.DeriveFrom != "REGISTRY_PASSWD" || derived.DeriveUsername != "harbor_registry_user" {
		t.Errorf("htpasswd derive fields not mapped: %+v", derived)
	}

	db := findSecret(t, app, "harbor-db-secret")
	cs := findField(t, db, "password")
	if cs.Derive != "cluster_secret" {
		t.Errorf("derive = %q, want cluster_secret", cs.Derive)
	}
	if cs.DeriveNamespace != "postgresql" || cs.DeriveSecret != "harbor-db-secret" || cs.DeriveKey != "password" {
		t.Errorf("cluster_secret derive fields not mapped: %+v", cs)
	}
}

func TestLoadConfigSensitiveTriState(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "harbor.yaml", v1WithDerives)
	app, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	db := findSecret(t, app, "harbor-db-secret")

	// username: explicit `sensitive: false` → non-nil pointer to false.
	username := findField(t, db, "username")
	if username.Sensitive == nil {
		t.Error("username.Sensitive should be non-nil (explicit false)")
	} else if *username.Sensitive {
		t.Error("username.Sensitive should be false")
	}

	// password: no `sensitive:` key → nil (meaning "use default policy: mask").
	password := findField(t, db, "password")
	if password.Sensitive != nil {
		t.Errorf("password.Sensitive should be nil (absent), got %v", *password.Sensitive)
	}
}

func TestLoadConfigLegacy(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "legacy.yaml", legacyConfig)

	app, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if app.AppName != "legacyapp" || app.Namespace != "legacyns" {
		t.Errorf("legacy metadata mapping wrong: %+v", app)
	}
	if len(app.Secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(app.Secrets))
	}
	secret := app.Secrets[0]
	if len(secret.Fields) != 2 {
		t.Fatalf("expected legacy keys to become 2 fields, got %d", len(secret.Fields))
	}
	// Legacy keys become fields whose Prompt defaults to the key name.
	for _, f := range secret.Fields {
		if f.Name != f.Prompt {
			t.Errorf("legacy field %q: prompt %q should default to the name", f.Name, f.Prompt)
		}
	}
}

func TestLoadConfigDispatchesByAPIVersion(t *testing.T) {
	dir := t.TempDir()
	// A file with the v1 apiVersion but ALSO legacy keys should be parsed as
	// v1 (header dispatch), so its legacy `app_name` is ignored.
	body := "apiVersion: kryptos.dev/v1\nkind: SecretConfig\n" +
		"metadata:\n  name: dispatchapp\n  namespace: dispatchns\n" +
		"app_name: should-be-ignored\nspec:\n  secrets: []\n"
	path := writeConfig(t, dir, "dispatch.yaml", body)

	app, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if app.AppName != "dispatchapp" {
		t.Errorf("apiVersion dispatch failed: AppName = %q, want dispatchapp", app.AppName)
	}
}

func TestLoadConfigDockerConfigJSON(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "ci.yaml", dockerConfigJSONConfig)
	app, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	secret := findSecret(t, app, "harbor-dockerconfig")
	if secret.Type != "kubernetes.io/dockerconfigjson" {
		t.Errorf("type = %q, want kubernetes.io/dockerconfigjson", secret.Type)
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestListConfigs(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "a.yaml", v1WithDerives)
	writeConfig(t, dir, "b.yaml", legacyConfig)
	// A non-YAML file must be ignored by the *.yaml glob.
	writeConfig(t, dir, "README.md", "not a config")

	got, err := ListConfigs(dir)
	if err != nil {
		t.Fatalf("ListConfigs: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 yaml configs, got %d: %v", len(got), got)
	}
	for _, p := range got {
		if filepath.Ext(p) != ".yaml" {
			t.Errorf("ListConfigs returned a non-yaml file: %s", p)
		}
	}
}

func TestListConfigsEmptyDir(t *testing.T) {
	got, err := ListConfigs(t.TempDir())
	if err != nil {
		t.Fatalf("ListConfigs on empty dir: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no configs, got %d", len(got))
	}
}
