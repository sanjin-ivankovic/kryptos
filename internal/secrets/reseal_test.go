package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sealedDoc = `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: app-secret
  namespace: app
spec:
  encryptedData:
    KEY: %s
    PASSWORD: %s
`

func sealedText(a, b string) string {
	return strings.Replace(strings.Replace(sealedDoc, "%s", a, 1), "%s", b, 1)
}

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app-sealed-secret.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResealFileReplacesCiphertext(t *testing.T) {
	path := writeTemp(t, sealedText("old1", "old2"))
	err := ResealFile(path, func(in []byte) ([]byte, error) {
		if !strings.Contains(string(in), "old1") {
			t.Errorf("the current file must be sent: %s", in)
		}
		return []byte(sealedText("new1", "new2")), nil
	})
	if err != nil {
		t.Fatalf("ResealFile: %v", err)
	}
	got, _ := os.ReadFile(path)
	if !strings.Contains(string(got), "new1") || strings.Contains(string(got), "old1") {
		t.Errorf("file not replaced:\n%s", got)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestResealFileRefusesAChangedKeySet(t *testing.T) {
	orig := sealedText("old1", "old2")
	path := writeTemp(t, orig)
	err := ResealFile(path, func([]byte) ([]byte, error) {
		return []byte(strings.Replace(sealedText("n1", "n2"), "PASSWORD", "OTHER", 1)), nil
	})
	if err == nil || !strings.Contains(err.Error(), "changed identity") {
		t.Fatalf("want an identity error, got %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != orig {
		t.Error("file must be left untouched")
	}
}

func TestResealFileKeepsTheFileOnAFailedCall(t *testing.T) {
	orig := sealedText("old1", "old2")
	path := writeTemp(t, orig)
	if err := ResealFile(path, func([]byte) ([]byte, error) { return nil, errors.New("controller down") }); err == nil {
		t.Fatal("want the re-encrypt error")
	}
	if got, _ := os.ReadFile(path); string(got) != orig {
		t.Error("file must be left untouched")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("no temp file may be left behind, got %d entries", len(entries))
	}
}

func TestResealFileRejectsANonSealedFile(t *testing.T) {
	path := writeTemp(t, "kind: ConfigMap\n")
	if err := ResealFile(path, func(b []byte) ([]byte, error) { return b, nil }); err == nil {
		t.Fatal("want a parse error for a file without encryptedData")
	}
}
