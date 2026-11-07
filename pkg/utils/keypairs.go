package utils

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// GenerateSelfSignedTLS produces a self-signed X.509 certificate and its
// private key, both PEM-encoded, suitable for a kubernetes.io/tls Secret
// (or any "I just need a cert" homelab case). commonName sets the subject CN;
// hosts are added as SANs (DNS names, or IPs when they parse as one). The cert
// is valid for ~10 years — homelab certs aren't rotated on the Let's Encrypt
// cadence, and a short lifetime would just create silent expiry surprises.
func GenerateSelfSignedTLS(commonName string, hosts []string) (certPEM, keyPEM string, err error) {
	if commonName == "" {
		return "", "", fmt.Errorf("tls: common name is required")
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("tls: generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("tls: serial: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, priv.Public(), priv)
	if err != nil {
		return "", "", fmt.Errorf("tls: create certificate: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("tls: marshal key: %w", err)
	}

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM, nil
}

// GenerateSSHKeypair produces an ed25519 SSH key pair: the private key in
// OpenSSH format and the public key in authorized_keys format. comment is
// appended to the public key (the usual "user@host" trailer); empty is fine.
func GenerateSSHKeypair(comment string) (privatePEM, publicAuthorizedKey string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("ssh_keypair: generate key: %w", err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return "", "", fmt.Errorf("ssh_keypair: marshal private key: %w", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", "", fmt.Errorf("ssh_keypair: public key: %w", err)
	}
	authorized := string(ssh.MarshalAuthorizedKey(sshPub))
	if comment != "" {
		// MarshalAuthorizedKey emits "<type> <base64>\n"; append the comment
		// before the newline so it reads like a normal authorized_keys line.
		authorized = fmt.Sprintf("%s %s\n", trimTrailingNewline(authorized), comment)
	}

	return string(pem.EncodeToMemory(pemBlock)), authorized, nil
}

// ReadFileString reads a file and returns its contents as a string.
func ReadFileString(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("file: read %s: %w", path, err)
	}
	return string(b), nil
}

func trimTrailingNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
