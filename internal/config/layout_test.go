package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// chdir switches into dir for the duration of the test and restores the old
// CWD afterwards. LoadLayout resolves relative to the CWD's repo root.
func chdir(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
}

// fakeRepo builds a temp dir with a .git marker so findRepoRootFromCWD stops
// there, plus any extra subdirectories requested. The returned path is
// symlink-resolved so it matches what os.Getwd reports after chdir (macOS maps
// /var → /private/var), keeping path equality checks honest.
func fakeRepo(t *testing.T, subdirs ...string) string {
	t.Helper()
	root := mustEval(t, t.TempDir())
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	for _, d := range subdirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	return root
}

func TestLoadLayoutDefaults(t *testing.T) {
	// With no kryptos.toml, the defaults must match the argo-apps directory
	// convention.
	root := fakeRepo(t)
	chdir(t, root)

	l, err := LoadLayout()
	if err != nil {
		t.Fatalf("LoadLayout: %v", err)
	}
	if l.RepoRoot != root {
		t.Errorf("RepoRoot = %q, want %q", l.RepoRoot, root)
	}
	if l.ConfigDir != filepath.Join(root, defaultConfigDir) {
		t.Errorf("ConfigDir = %q, want %q", l.ConfigDir, filepath.Join(root, defaultConfigDir))
	}
	if l.ControllerNamespace != defaultControllerNamespace {
		t.Errorf("ControllerNamespace = %q, want %q", l.ControllerNamespace, defaultControllerNamespace)
	}
	if len(l.Sections) != 2 || l.Sections[0] != "apps" || l.Sections[1] != "infrastructure" {
		t.Errorf("Sections = %v, want [apps infrastructure]", l.Sections)
	}
}

func TestLoadLayoutFromTOML(t *testing.T) {
	root := fakeRepo(t)
	toml := `
config_dir = "secrets/configs"
output_layout = "manifests/{section}/{app}/sealed/{name}"
sections = ["base", "overlays"]
controller_namespace = "sealed-secrets"
`
	if err := os.WriteFile(filepath.Join(root, "kryptos.toml"), []byte(toml), 0o600); err != nil {
		t.Fatalf("write toml: %v", err)
	}
	chdir(t, root)

	l, err := LoadLayout()
	if err != nil {
		t.Fatalf("LoadLayout: %v", err)
	}
	if l.ConfigDir != filepath.Join(root, "secrets/configs") {
		t.Errorf("ConfigDir = %q", l.ConfigDir)
	}
	if l.OutputLayout != "manifests/{section}/{app}/sealed/{name}" {
		t.Errorf("OutputLayout = %q", l.OutputLayout)
	}
	if l.ControllerNamespace != "sealed-secrets" {
		t.Errorf("ControllerNamespace = %q", l.ControllerNamespace)
	}
	if len(l.Sections) != 2 || l.Sections[0] != "base" {
		t.Errorf("Sections = %v", l.Sections)
	}
}

func TestLoadLayoutPartialTOMLFillsDefaults(t *testing.T) {
	root := fakeRepo(t)
	// Only override the controller namespace; everything else defaults.
	if err := os.WriteFile(filepath.Join(root, "kryptos.toml"),
		[]byte("controller_namespace = \"custom-ns\"\n"), 0o600); err != nil {
		t.Fatalf("write toml: %v", err)
	}
	chdir(t, root)

	l, err := LoadLayout()
	if err != nil {
		t.Fatalf("LoadLayout: %v", err)
	}
	if l.ControllerNamespace != "custom-ns" {
		t.Errorf("ControllerNamespace = %q, want custom-ns", l.ControllerNamespace)
	}
	if l.ConfigDir != filepath.Join(root, defaultConfigDir) {
		t.Errorf("ConfigDir should default, got %q", l.ConfigDir)
	}
	if l.OutputLayout != defaultOutputLayout {
		t.Errorf("OutputLayout should default, got %q", l.OutputLayout)
	}
}

func TestLoadLayoutMalformedTOML(t *testing.T) {
	root := fakeRepo(t)
	if err := os.WriteFile(filepath.Join(root, "kryptos.toml"),
		[]byte("config_dir = \"unterminated\n"), 0o600); err != nil {
		t.Fatalf("write toml: %v", err)
	}
	chdir(t, root)

	if _, err := LoadLayout(); err == nil {
		t.Fatal("expected an error for malformed TOML")
	}
}

func TestLayoutSecretsDirPicksExistingSection(t *testing.T) {
	// Default layout: the app lives under cluster/infrastructure (the SECOND
	// section), so the resolver must skip apps and find infrastructure.
	root := fakeRepo(t, "cluster/infrastructure/harbor")
	chdir(t, root)

	l, err := LoadLayout()
	if err != nil {
		t.Fatalf("LoadLayout: %v", err)
	}
	dir, err := l.SecretsDir("harbor")
	if err != nil {
		t.Fatalf("SecretsDir: %v", err)
	}
	want := filepath.Join(root, "cluster", "infrastructure", "harbor", "secrets")
	if dir != want {
		t.Errorf("SecretsDir = %q, want %q", dir, want)
	}
	// It must have created the secrets dir.
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Errorf("secrets dir not created: %v", err)
	}
}

func TestLayoutSecretsDirPrefersFirstSection(t *testing.T) {
	// When the app exists under BOTH sections, the first (apps) wins.
	root := fakeRepo(t, "cluster/apps/freshrss", "cluster/infrastructure/freshrss")
	chdir(t, root)

	l, _ := LoadLayout()
	dir, err := l.SecretsDir("freshrss")
	if err != nil {
		t.Fatalf("SecretsDir: %v", err)
	}
	if !strings.Contains(dir, filepath.Join("cluster", "apps", "freshrss")) {
		t.Errorf("expected apps section to win, got %q", dir)
	}
}

func TestLayoutSecretsDirMissingApp(t *testing.T) {
	root := fakeRepo(t, "cluster/apps/other")
	chdir(t, root)

	l, _ := LoadLayout()
	if _, err := l.SecretsDir("ghost"); err == nil {
		t.Fatal("expected an error for an app with no section directory")
	}
}

func TestLayoutOutputPath(t *testing.T) {
	root := fakeRepo(t, "cluster/apps/valkey")
	chdir(t, root)

	l, _ := LoadLayout()
	got, err := l.OutputPath("valkey", &Secret{Name: "valkey-auth"})
	if err != nil {
		t.Fatalf("OutputPath: %v", err)
	}
	want := filepath.Join(root, "cluster", "apps", "valkey", "secrets", "valkey-auth-sealed-secret.yaml")
	if got != want {
		t.Errorf("OutputPath = %q, want %q", got, want)
	}
}

func TestSealedFilename(t *testing.T) {
	cases := []struct {
		name   string
		secret Secret
		want   string
	}{
		{"strips a trailing -secret", Secret{Name: "harbor-registry-secret"}, "harbor-registry-sealed-secret.yaml"},
		{"name without -secret suffix", Secret{Name: "valkey-auth"}, "valkey-auth-sealed-secret.yaml"},
		{"explicit filename wins", Secret{Name: "anything", Filename: "custom.yaml"}, "custom.yaml"},
		{"only the trailing -secret is stripped", Secret{Name: "secret-store-secret"}, "secret-store-sealed-secret.yaml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SealedFilename(&tc.secret); got != tc.want {
				t.Errorf("SealedFilename(%q) = %q, want %q", tc.secret.Name, got, tc.want)
			}
		})
	}
}

func mustEval(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return p
	}
	return r
}
