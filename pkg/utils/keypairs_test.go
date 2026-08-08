package utils

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerateSelfSignedTLS(t *testing.T) {
	t.Run("requires a common name", func(t *testing.T) {
		if _, _, err := GenerateSelfSignedTLS("", nil); err == nil {
			t.Fatal("expected an error for an empty common name")
		}
	})

	t.Run("produces a parseable cert with the CN and SANs", func(t *testing.T) {
		certPEM, keyPEM, err := GenerateSelfSignedTLS("svc.example.com",
			[]string{"svc.example.com", "10.0.0.1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		block, _ := pem.Decode([]byte(certPEM))
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatalf("cert is not a CERTIFICATE PEM block")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("cert does not parse: %v", err)
		}
		if cert.Subject.CommonName != "svc.example.com" {
			t.Errorf("CN = %q, want svc.example.com", cert.Subject.CommonName)
		}
		if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "svc.example.com" {
			t.Errorf("DNS SANs = %v", cert.DNSNames)
		}
		if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "10.0.0.1" {
			t.Errorf("IP SANs = %v, want [10.0.0.1]", cert.IPAddresses)
		}

		keyBlock, _ := pem.Decode([]byte(keyPEM))
		if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
			t.Fatalf("key is not a PRIVATE KEY PEM block")
		}
		if _, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err != nil {
			t.Errorf("key does not parse as PKCS8: %v", err)
		}
	})

	t.Run("produces distinct certs", func(t *testing.T) {
		a, _, _ := GenerateSelfSignedTLS("x", nil)
		b, _, _ := GenerateSelfSignedTLS("x", nil)
		if a == b {
			t.Error("two certs for the same CN should differ (random serial/key)")
		}
	})
}

func TestGenerateSSHKeypair(t *testing.T) {
	t.Run("private key parses and public key is valid", func(t *testing.T) {
		priv, pub, err := GenerateSSHKeypair("kryptos@example")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		signer, err := ssh.ParsePrivateKey([]byte(priv))
		if err != nil {
			t.Fatalf("private key does not parse: %v", err)
		}
		parsedPub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
		if err != nil {
			t.Fatalf("public key is not a valid authorized_keys line: %v", err)
		}
		if comment != "kryptos@example" {
			t.Errorf("comment = %q, want kryptos@example", comment)
		}
		// The public key from the line must match the signer's public key.
		if string(parsedPub.Marshal()) != string(signer.PublicKey().Marshal()) {
			t.Error("public key does not match the private key")
		}
	})

	t.Run("works without a comment", func(t *testing.T) {
		priv, pub, err := GenerateSSHKeypair("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.HasPrefix(pub, "ssh-ed25519 ") {
			t.Errorf("public key should start with ssh-ed25519, got %q", pub)
		}
		if _, err := ssh.ParsePrivateKey([]byte(priv)); err != nil {
			t.Errorf("private key does not parse: %v", err)
		}
	})

	t.Run("produces distinct keypairs", func(t *testing.T) {
		a, _, _ := GenerateSSHKeypair("")
		b, _, _ := GenerateSSHKeypair("")
		if a == b {
			t.Error("two keypairs should differ")
		}
	})
}

func TestReadFileString(t *testing.T) {
	t.Run("reads contents", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "f.txt")
		if err := os.WriteFile(path, []byte("hello\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		got, err := ReadFileString(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "hello\n" {
			t.Errorf("got %q, want hello\\n", got)
		}
	})

	t.Run("errors on a missing file", func(t *testing.T) {
		if _, err := ReadFileString(filepath.Join(t.TempDir(), "nope")); err == nil {
			t.Fatal("expected an error for a missing file")
		}
	})
}
