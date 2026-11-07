package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"source.example.com/example-org/kryptos/internal/secrets"
)

const demoConfig = `apiVersion: kryptos.dev/v1
kind: SecretConfig
metadata:
  name: demo
  namespace: demo
spec:
  secrets:
    - name: demo-secret
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

const demoSealed = `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: demo-secret
  namespace: demo
spec:
  encryptedData:
    KEY: AgB1
    PASSWORD: AgB2
`

// demoRepo builds a repo with one app config and chdirs into it. sealed
// writes the app's sealed file.
func demoRepo(t *testing.T, sealed bool) string {
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
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	write("kryptos.toml", "config_dir = \"kryptos/configs\"\noutput_layout = \"apps/{section}/{app}/secrets/{name}\"\nsections = [\"user\"]\n")
	write("kryptos/configs/demo.yaml", demoConfig)
	if err := os.MkdirAll(filepath.Join(root, "apps/user/demo/secrets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if sealed {
		write("apps/user/demo/secrets/demo-sealed-secret.yaml", demoSealed)
	}
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
	return root
}

// resetFlags puts every package-level flag variable back to its default; cobra
// keeps them between Execute calls in one process.
func resetFlags() {
	configDir, controllerNamespace, dryRun, logLevel, verbose, certFile = "", "kube-system", false, "", false, ""
	sealValuesFile, sealSetFlags, sealAll, sealForce, allowImmutable = "", nil, false, false, false
	rotateApp, rotateSecret, rotateFields = "", "", nil
	resealAll, statusOutput, certOut = false, "text", ""
}

// run executes the CLI with args and returns its stdout and error.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	resetFlags()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	rootCmd.SetArgs(args)
	runErr := rootCmd.Execute()
	_ = w.Close()
	os.Stdout = stdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String(), runErr
}

func TestValidateAuditDiffStatusOnACleanRepo(t *testing.T) {
	demoRepo(t, true)
	for _, args := range [][]string{{"validate"}, {"audit"}, {"diff"}, {"status"}} {
		if out, err := run(t, args...); err != nil {
			t.Errorf("%v: %v\n%s", args, err, out)
		}
	}
}

func TestStatusJSONReportsAnUnsealedSecret(t *testing.T) {
	demoRepo(t, false)
	out, err := run(t, "status", "--output", "json")
	if err == nil {
		t.Fatal("status must fail on a never-sealed secret")
	}
	var st struct {
		OK      bool `json:"ok"`
		Secrets []struct {
			Secret    string   `json:"secret"`
			Sealed    bool     `json:"sealed"`
			Immutable []string `json:"immutable"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if st.OK || len(st.Secrets) != 1 || st.Secrets[0].Sealed || st.Secrets[0].Immutable[0] != "KEY" {
		t.Errorf("unexpected report: %+v", st)
	}
	if _, err := run(t, "status", "--output", "yaml"); err == nil {
		t.Error("an unknown --output must fail")
	}
}

func TestAuditAndDiffFailOnDrift(t *testing.T) {
	root := demoRepo(t, true)
	sealed := filepath.Join(root, "apps/user/demo/secrets/demo-sealed-secret.yaml")
	if err := os.WriteFile(sealed, []byte(strings.Replace(demoSealed, "PASSWORD", "OLD", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "diff"); err == nil {
		t.Error("diff must fail on a changed key set")
	}
	if err := os.WriteFile(filepath.Join(root, "apps/user/demo/secrets/stray-sealed-secret.yaml"), []byte(demoSealed), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "audit"); err == nil {
		t.Error("audit must fail on an orphaned sealed file")
	}
}

func TestSealDryRunAndTheResealGuards(t *testing.T) {
	demoRepo(t, false)
	if out, err := run(t, "seal", "demo", "demo-secret", "--dry-run"); err != nil {
		t.Fatalf("first seal: %v\n%s", err, out)
	}

	demoRepo(t, true)
	// Dry-run writes nothing, so it skips the "file exists" prompt; the
	// immutable guard still refuses to preview a new KEY.
	out, err := run(t, "seal", "demo", "demo-secret", "--dry-run")
	if err == nil || !strings.Contains(out, "immutable field(s) KEY") {
		t.Errorf("dry-run on a sealed secret must still refuse the immutable key: %v\n%s", err, out)
	}
	out, err = run(t, "seal", "demo", "demo-secret", "--dry-run", "--force")
	if err == nil || !strings.Contains(out, "immutable field(s) KEY") {
		t.Errorf("--force must not regenerate an immutable key: %v\n%s", err, out)
	}
	if out, err := run(t, "seal", "demo", "demo-secret", "--dry-run", "--force", "--set", "KEY=current"); err != nil {
		t.Errorf("--force with the current value must pass: %v\n%s", err, out)
	}
	if _, err := run(t, "seal", "demo"); err == nil {
		t.Error("seal without a secret or --all must fail")
	}
}

func TestRotateDryRunGuards(t *testing.T) {
	demoRepo(t, true)
	if _, err := run(t, "rotate", "--app", "demo", "--secret", "demo-secret", "--dry-run"); err == nil {
		t.Error("rotating every field must refuse the immutable key")
	}
	if out, err := run(t, "rotate", "--app", "demo", "--secret", "demo-secret", "--dry-run",
		"--field", "PASSWORD", "--set", "KEY=current"); err != nil {
		t.Errorf("rotating only PASSWORD must pass: %v\n%s", err, out)
	}
	if out, err := run(t, "rotate", "--app", "demo", "--secret", "demo-secret", "--dry-run", "--allow-immutable"); err != nil {
		t.Errorf("--allow-immutable must pass: %v\n%s", err, out)
	}
	if _, err := run(t, "rotate", "--app", "demo"); err == nil {
		t.Error("rotate without --secret must fail")
	}
}

func TestResealDryRun(t *testing.T) {
	root := demoRepo(t, true)
	out, err := run(t, "reseal", "--all", "--dry-run")
	if err != nil || !strings.Contains(out, filepath.Join("apps", "user", "demo", "secrets", "demo-sealed-secret.yaml")) ||
		!strings.Contains(out, "1 sealed file(s) would be re-encrypted") {
		t.Errorf("dry-run must list the file: %v\n%s", err, out)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "apps/user/demo/secrets/demo-sealed-secret.yaml")); string(got) != demoSealed {
		t.Error("dry-run must not touch the file")
	}
	if _, err := run(t, "reseal"); err == nil {
		t.Error("reseal without apps or --all must fail")
	}
	if _, err := run(t, "reseal", "ghost", "--dry-run"); err == nil {
		t.Error("an unknown app must fail")
	}
}

func TestCertFetchNeedsADestination(t *testing.T) {
	demoRepo(t, true)
	if _, err := run(t, "cert", "fetch"); err == nil || !strings.Contains(err.Error(), "no destination") {
		t.Errorf("want a no-destination error, got %v", err)
	}
}

func TestCertFlagNeedsAnExistingFile(t *testing.T) {
	demoRepo(t, false)
	_, err := run(t, "seal", "demo", "demo-secret", "--cert", "missing.pem")
	if err == nil || !strings.Contains(err.Error(), "kryptos cert fetch") {
		t.Errorf("a missing certificate must point at cert fetch, got %v", err)
	}
}

func TestRefuseResealNamesTheKeys(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	ok := refuseReseal(secrets.ResealWarning{
		App: "demo", Secret: "demo-secret", Filename: "demo-sealed-secret.yaml",
		Regenerated: []string{"KEY", "PASSWORD"}, Preserved: []string{"USER"}, Immutable: []string{"KEY"},
	})
	_ = w.Close()
	os.Stdout = stdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	out := buf.String()
	if ok {
		t.Error("the hook must decline")
	}
	for _, want := range []string{"REGENERATE", "- PASSWORD", "preserved: USER", "immutable (kept even with --force): KEY", "kryptos add demo demo-secret"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
