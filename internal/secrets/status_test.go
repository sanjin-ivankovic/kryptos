package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"source.example.com/example-org/kryptos/internal/config"
)

const statusConfig = `apiVersion: kryptos.dev/v1
kind: SecretConfig
metadata:
  name: %s
  namespace: %s
spec:
  secrets:
    - name: %s-secret
      type: Opaque
      fields:
        - name: KEY
          generator: apikey
          required: true
          immutable: true
        - name: PASSWORD
          generator: secure
          required: true
`

func sealedWith(keys ...string) string {
	body := "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nspec:\n  encryptedData:\n"
	for _, k := range keys {
		body += "    " + k + ": AgB\n"
	}
	return body
}

func statusRepo(t *testing.T) (*config.Layout, string) {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, app := range []string{"good", "drift", "unsealed"} {
		write("configs/"+app+".yaml", fmt.Sprintf(statusConfig, app, app, app))
		if err := os.MkdirAll(filepath.Join(root, "apps", "user", app, "secrets"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("apps/user/good/secrets/good-sealed-secret.yaml", sealedWith("KEY", "PASSWORD"))
	write("apps/user/drift/secrets/drift-sealed-secret.yaml", sealedWith("KEY", "OLD"))
	write("apps/user/good/secrets/stray-sealed-secret.yaml", sealedWith("X"))
	write("configs/broken.yaml", "apiVersion: kryptos.dev/v1\nkind: SecretConfig\nmetadata:\n  name: broken\n  namespace: b\nspec:\n  secrets:\n    - name: s\n      fields:\n        - name: f\n          generator: bogus\n")
	return &config.Layout{
		RepoRoot:     root,
		ConfigDir:    filepath.Join(root, "configs"),
		OutputLayout: "apps/{section}/{app}/secrets/{name}",
		Sections:     []string{"user"},
	}, root
}

func TestBuildStatus(t *testing.T) {
	layout, _ := statusRepo(t)
	st, err := BuildStatus(layout)
	if err != nil {
		t.Fatalf("BuildStatus: %v", err)
	}
	if st.OK || st.Configs != 4 {
		t.Fatalf("OK=%v Configs=%d", st.OK, st.Configs)
	}
	by := map[string]SecretStatus{}
	for _, s := range st.Secrets {
		by[s.App] = s
	}
	if g := by["good"]; !g.Sealed || g.Problem() || len(g.Immutable) != 1 || g.Immutable[0] != "KEY" {
		t.Errorf("good = %+v", g)
	}
	if d := by["drift"]; len(d.MissingKeys) != 1 || d.MissingKeys[0] != "PASSWORD" || len(d.OrphanedKeys) != 1 || d.OrphanedKeys[0] != "OLD" {
		t.Errorf("drift = %+v", d)
	}
	if u := by["unsealed"]; u.Sealed || !u.Problem() {
		t.Errorf("unsealed = %+v", u)
	}
	if len(st.OrphanedFiles) != 1 || st.OrphanedFiles[0] != "good/stray-sealed-secret.yaml" {
		t.Errorf("OrphanedFiles = %v", st.OrphanedFiles)
	}
	if len(st.InvalidConfigs) != 1 || st.InvalidConfigs[0].File != "broken.yaml" {
		t.Errorf("InvalidConfigs = %+v", st.InvalidConfigs)
	}
	// drift + unsealed + orphan + the broken config's errors (its secret has no
	// app dir, which also counts).
	if st.Problems < 4 {
		t.Errorf("Problems = %d, want at least 4", st.Problems)
	}
}

func TestBuildStatusClean(t *testing.T) {
	layout, root := statusRepo(t)
	for _, f := range []string{"configs/drift.yaml", "configs/unsealed.yaml", "configs/broken.yaml",
		"apps/user/good/secrets/stray-sealed-secret.yaml"} {
		if err := os.Remove(filepath.Join(root, f)); err != nil {
			t.Fatal(err)
		}
	}
	st, err := BuildStatus(layout)
	if err != nil {
		t.Fatalf("BuildStatus: %v", err)
	}
	if !st.OK || st.Problems != 0 || len(st.Secrets) != 1 {
		t.Fatalf("want a clean report, got %+v", st)
	}
}
