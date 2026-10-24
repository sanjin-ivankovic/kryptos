package kubeseal

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestHelperProcess is the standard Go pattern for faking exec.Command: the
// test re-execs its own binary with GO_WANT_HELPER_PROCESS=1, and this function
// impersonates kubeseal. It echoes its args (so arg-construction can be
// asserted), copies stdin to stdout prefixed (so the stdin pipe can be checked),
// and honours env-driven failure injection.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	// Fail on demand to exercise the error path.
	if os.Getenv("HELPER_FAIL") == "1" {
		fmt.Fprintln(os.Stderr, "fake kubeseal: boom")
		os.Exit(3)
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	// Echo args so the caller can assert on argument construction.
	_, _ = fmt.Fprintf(os.Stdout, "ARGS:%s\n", strings.Join(args, " "))
	// Echo stdin so the caller can assert the secret was piped in.
	if in, _ := io.ReadAll(os.Stdin); len(in) > 0 {
		_, _ = fmt.Fprintf(os.Stdout, "STDIN:%s\n", string(in))
	}
	os.Exit(0)
}

// fakeExecCommand returns an execCommand replacement that runs TestHelperProcess
// instead of the real binary. extraEnv is appended to the child's environment.
func fakeExecCommand(extraEnv ...string) func(string, ...string) *exec.Cmd {
	return func(name string, args ...string) *exec.Cmd {
		cs := append([]string{"-test.run=TestHelperProcess", "--", name}, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
		cmd.Env = append(cmd.Env, extraEnv...)
		return cmd
	}
}

// withSeams swaps the package seams for the duration of fn and restores them.
func withSeams(t *testing.T, lp func(string) (string, error), ec func(string, ...string) *exec.Cmd) {
	t.Helper()
	origLook, origExec := lookPath, execCommand
	lookPath, execCommand = lp, ec
	t.Cleanup(func() { lookPath, execCommand = origLook, origExec })
}

func TestNewSealer(t *testing.T) {
	t.Run("errors when kubeseal is missing", func(t *testing.T) {
		withSeams(t,
			func(string) (string, error) { return "", fmt.Errorf("not found") },
			fakeExecCommand(),
		)
		if _, err := NewSealer("kube-system"); err == nil {
			t.Fatal("expected an error when kubeseal binary is absent")
		}
	})

	t.Run("defaults the controller namespace to kube-system", func(t *testing.T) {
		withSeams(t,
			func(string) (string, error) { return "/usr/bin/kubeseal", nil },
			fakeExecCommand(),
		)
		s, err := NewSealer("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if s.ControllerNamespace != "kube-system" {
			t.Errorf("controller namespace = %q, want kube-system", s.ControllerNamespace)
		}
	})

	t.Run("keeps an explicit controller namespace", func(t *testing.T) {
		withSeams(t,
			func(string) (string, error) { return "/usr/bin/kubeseal", nil },
			fakeExecCommand(),
		)
		s, err := NewSealer("sealed-secrets")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if s.ControllerNamespace != "sealed-secrets" {
			t.Errorf("controller namespace = %q, want sealed-secrets", s.ControllerNamespace)
		}
	})
}

func TestSeal(t *testing.T) {
	t.Run("constructs args and pipes the secret in via stdin", func(t *testing.T) {
		withSeams(t,
			func(string) (string, error) { return "/usr/bin/kubeseal", nil },
			fakeExecCommand(),
		)
		s, err := NewSealer("sealed-secrets")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		out, err := s.Seal([]byte("RAW-SECRET-YAML"), "harbor", "harbor-core-secret")
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		got := string(out)
		// Argument construction.
		for _, want := range []string{
			"--format yaml",
			"--controller-namespace sealed-secrets",
			"--name harbor-core-secret",
			"--namespace harbor",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("expected args to contain %q; full output:\n%s", want, got)
			}
		}
		// Stdin pipe.
		if !strings.Contains(got, "STDIN:RAW-SECRET-YAML") {
			t.Errorf("expected the raw secret on stdin; full output:\n%s", got)
		}
	})

	t.Run("surfaces stderr on failure", func(t *testing.T) {
		withSeams(t,
			func(string) (string, error) { return "/usr/bin/kubeseal", nil },
			fakeExecCommand("HELPER_FAIL=1"),
		)
		s, err := NewSealer("sealed-secrets")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_, err = s.Seal([]byte("x"), "ns", "name")
		if err == nil {
			t.Fatal("expected an error when kubeseal exits non-zero")
		}
		if !strings.Contains(err.Error(), "boom") {
			t.Errorf("expected kubeseal stderr surfaced in the error, got: %v", err)
		}
	})
}

// capturingSealer builds a Sealer wired to the fake kubeseal, plus a buffer the
// helper's stdout lands in so the test can assert on args and stdin.
func TestSealRawInto(t *testing.T) {
	t.Run("merges into the target file and never passes --raw", func(t *testing.T) {
		var captured string
		withSeams(t,
			func(string) (string, error) { return "/usr/bin/kubeseal", nil },
			func(name string, args ...string) *exec.Cmd {
				cs := append([]string{"-test.run=TestHelperProcess", "--", name}, args...)
				cmd := exec.Command(os.Args[0], cs...)
				cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
				captured = strings.Join(args, " ")
				return cmd
			},
		)
		s, err := NewSealer("sealed-secrets")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := s.SealRawInto([]byte("NEW-VALUE"), "authelia", "authelia-oidc-secret",
			"omni.client.secret", "/tmp/authelia-oidc-sealed-secret.yaml"); err != nil {
			t.Fatalf("SealRawInto: %v", err)
		}

		for _, want := range []string{
			"--format yaml",
			"--controller-namespace sealed-secrets",
			"--scope strict",
			"--merge-into /tmp/authelia-oidc-sealed-secret.yaml",
		} {
			if !strings.Contains(captured, want) {
				t.Errorf("expected args to contain %q; got: %s", want, captured)
			}
		}
		// kubeseal dispatches --merge-into BEFORE the --raw branch, so passing
		// --raw would make the value silently unread ("no secrets found").
		if strings.Contains(captured, "--raw") {
			t.Errorf("--raw must not be combined with --merge-into; got: %s", captured)
		}
		if strings.Contains(captured, "--from-file") {
			t.Errorf("--from-file is ignored with --merge-into; got: %s", captured)
		}
	})

	t.Run("pipes a one-key Secret manifest with the value base64-encoded", func(t *testing.T) {
		// A value containing a newline: base64 under `data:` must carry it
		// through intact, where `stringData:` would need quoting/indentation.
		value := []byte("line1\nline2")
		got := oneKeySecretManifest(value, "ns", "demo-secret", "pem.key")

		wantB64 := base64.StdEncoding.EncodeToString(value)
		for _, want := range []string{
			"kind: Secret",
			"name: demo-secret",
			"namespace: ns",
			"data:",
			"pem.key: " + wantB64,
		} {
			if !strings.Contains(got, want) {
				t.Errorf("expected manifest to contain %q; got:\n%s", want, got)
			}
		}
		if strings.Contains(got, "stringData:") {
			t.Errorf("manifest must use base64 data:, not stringData; got:\n%s", got)
		}
	})

	t.Run("pipes the manifest to kubeseal on stdin", func(t *testing.T) {
		withSeams(t,
			func(string) (string, error) { return "/usr/bin/kubeseal", nil },
			fakeExecCommand(),
		)
		s, err := NewSealer("sealed-secrets")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// The fake helper exits 0 and echoes stdin; a nil error proves the
		// manifest was accepted and piped without the method erroring.
		if err := s.SealRawInto([]byte("v"), "ns", "demo-secret", "field", "/tmp/x.yaml"); err != nil {
			t.Fatalf("SealRawInto: %v", err)
		}
	})

	t.Run("validates required arguments", func(t *testing.T) {
		withSeams(t,
			func(string) (string, error) { return "/usr/bin/kubeseal", nil },
			fakeExecCommand(),
		)
		s, _ := NewSealer("sealed-secrets")
		if err := s.SealRawInto([]byte("v"), "ns", "name", "", "/tmp/x.yaml"); err == nil {
			t.Error("expected an error when the field name is empty")
		}
		if err := s.SealRawInto([]byte("v"), "ns", "name", "field", ""); err == nil {
			t.Error("expected an error when the target file is empty")
		}
	})

	t.Run("surfaces stderr on failure", func(t *testing.T) {
		withSeams(t,
			func(string) (string, error) { return "/usr/bin/kubeseal", nil },
			fakeExecCommand("HELPER_FAIL=1"),
		)
		s, _ := NewSealer("sealed-secrets")
		err := s.SealRawInto([]byte("v"), "ns", "name", "field", "/tmp/x.yaml")
		if err == nil {
			t.Fatal("expected an error when kubeseal exits non-zero")
		}
		if !strings.Contains(err.Error(), "boom") {
			t.Errorf("expected kubeseal stderr surfaced, got: %v", err)
		}
	})
}
