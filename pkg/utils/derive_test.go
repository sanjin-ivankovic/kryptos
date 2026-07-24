package utils

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestRenderTemplate(t *testing.T) {
	t.Run("substitutes sibling field values", func(t *testing.T) {
		body := "redis://:{{ .password }}@valkey:6379/1"
		got, err := RenderTemplate(body, map[string]string{"password": "hunter2"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "redis://:hunter2@valkey:6379/1"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("references multiple siblings", func(t *testing.T) {
		body := "{{ .user }}:{{ .pass }}"
		got, err := RenderTemplate(body, map[string]string{"user": "admin", "pass": "secret"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "admin:secret" {
			t.Errorf("got %q, want %q", got, "admin:secret")
		}
	})

	t.Run("errors on a missing key rather than rendering <no value>", func(t *testing.T) {
		// missingkey=error is the whole point: a typo'd {{ .typo }} must fail
		// loudly instead of baking "<no value>" into a sealed secret.
		_, err := RenderTemplate("{{ .typo }}", map[string]string{"password": "x"})
		if err == nil {
			t.Fatal("expected an error for a missing key, got nil")
		}
	})

	t.Run("errors on an unparseable template", func(t *testing.T) {
		_, err := RenderTemplate("{{ .unterminated", map[string]string{})
		if err == nil {
			t.Fatal("expected a parse error, got nil")
		}
		if !strings.Contains(err.Error(), "parse template") {
			t.Errorf("expected a parse-template error, got: %v", err)
		}
	})

	t.Run("preserves a body with no template actions", func(t *testing.T) {
		body := "plain: text\nwith: yaml\n"
		got, err := RenderTemplate(body, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != body {
			t.Errorf("got %q, want %q", got, body)
		}
	})
}

func TestEscapeJSONPathSegment(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"no dots passes through", "password", "password"},
		{"single dot is escaped", "tls.crt", `tls\.crt`},
		{"multiple dots are all escaped", "a.b.c", `a\.b\.c`},
		{"hyphen and underscore untouched", "redis_password-1", "redis_password-1"},
		{"empty stays empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := escapeJSONPathSegment(tc.in); got != tc.want {
				t.Errorf("escapeJSONPathSegment(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestHelperProcess impersonates kubectl. It emits the base64-encoded value
// configured via HELPER_STDOUT (kubectl's jsonpath returns the raw base64 from
// .data), or fails when HELPER_FAIL=1 (e.g. secret/key not found).
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	if os.Getenv("HELPER_FAIL") == "1" {
		fmt.Fprintln(os.Stderr, `Error from server (NotFound): secrets "x" not found`)
		os.Exit(1)
	}
	// HELPER_STDOUT is already base64 (mimics .data.<key> which is base64).
	_, _ = fmt.Fprint(os.Stdout, os.Getenv("HELPER_STDOUT"))
	os.Exit(0)
}

func fakeExecCommand(extraEnv ...string) func(string, ...string) *exec.Cmd {
	return func(name string, args ...string) *exec.Cmd {
		cs := append([]string{"-test.run=TestHelperProcess", "--", name}, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
		cmd.Env = append(cmd.Env, extraEnv...)
		return cmd
	}
}

func withSeams(t *testing.T, lp func(string) (string, error), ec func(string, ...string) *exec.Cmd) {
	t.Helper()
	origLook, origExec := lookPath, execCommand
	lookPath, execCommand = lp, ec
	t.Cleanup(func() { lookPath, execCommand = origLook, origExec })
}

func TestFetchClusterSecret(t *testing.T) {
	t.Run("requires namespace, name, and key", func(t *testing.T) {
		cases := [][3]string{
			{"", "name", "key"},
			{"ns", "", "key"},
			{"ns", "name", ""},
		}
		for _, c := range cases {
			if _, err := FetchClusterSecret(c[0], c[1], c[2]); err == nil {
				t.Errorf("expected error for (%q,%q,%q)", c[0], c[1], c[2])
			}
		}
	})

	t.Run("errors when kubectl is missing", func(t *testing.T) {
		withSeams(t,
			func(string) (string, error) { return "", fmt.Errorf("not found") },
			fakeExecCommand(),
		)
		if _, err := FetchClusterSecret("ns", "name", "key"); err == nil {
			t.Fatal("expected an error when kubectl is absent")
		}
	})

	t.Run("base64-decodes the returned value", func(t *testing.T) {
		const plain = "super-secret-password"
		encoded := base64.StdEncoding.EncodeToString([]byte(plain))
		withSeams(t,
			func(string) (string, error) { return "/usr/bin/kubectl", nil },
			fakeExecCommand("HELPER_STDOUT="+encoded),
		)
		got, err := FetchClusterSecret("valkey", "valkey-auth", "password")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != plain {
			t.Errorf("got %q, want %q", got, plain)
		}
	})

	t.Run("empty result is treated as not-found", func(t *testing.T) {
		withSeams(t,
			func(string) (string, error) { return "/usr/bin/kubectl", nil },
			fakeExecCommand("HELPER_STDOUT="),
		)
		if _, err := FetchClusterSecret("ns", "name", "key"); err == nil {
			t.Fatal("expected a not-found error for an empty kubectl result")
		}
	})

	t.Run("surfaces kubectl stderr on failure", func(t *testing.T) {
		withSeams(t,
			func(string) (string, error) { return "/usr/bin/kubectl", nil },
			fakeExecCommand("HELPER_FAIL=1"),
		)
		_, err := FetchClusterSecret("ns", "name", "key")
		if err == nil {
			t.Fatal("expected an error when kubectl exits non-zero")
		}
		if !strings.Contains(err.Error(), "NotFound") {
			t.Errorf("expected kubectl stderr surfaced, got: %v", err)
		}
	})
}
