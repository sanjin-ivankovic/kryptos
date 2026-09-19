package kubeseal

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
)

// execCommand and lookPath are package-level seams so tests can intercept the
// shell-out to kubeseal without a real binary on PATH. Production code uses the
// os/exec implementations; tests swap them for fakes (see kubeseal_test.go).
var (
	execCommand = exec.Command
	lookPath    = exec.LookPath
)

// Sealer handles interactions with the kubeseal binary
type Sealer struct {
	BinaryPath          string
	ControllerNamespace string
}

// NewSealer creates a new Sealer instance with the given controller namespace
func NewSealer(controllerNamespace string) (*Sealer, error) {
	path, err := lookPath("kubeseal")
	if err != nil {
		return nil, fmt.Errorf("kubeseal binary not found in PATH: %w", err)
	}
	if controllerNamespace == "" {
		controllerNamespace = "kube-system"
	}
	return &Sealer{BinaryPath: path, ControllerNamespace: controllerNamespace}, nil
}

// CheckConnectivity verifies if kubeseal can reach the controller
func (s *Sealer) CheckConnectivity() error {
	// kubeseal --fetch-cert is a good way to check connectivity
	cmd := execCommand(s.BinaryPath, "--fetch-cert")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to connect to sealed-secrets controller: %v\nOutput: %s", err, string(output))
	}
	return nil
}

// Seal generates a SealedSecret from a raw K8s Secret
// input: The raw Secret YAML content
// output: The SealedSecret YAML content
func (s *Sealer) Seal(input []byte, namespace string, name string) ([]byte, error) {
	args := []string{
		"--format", "yaml",
		"--controller-namespace", s.ControllerNamespace,
		"--name", name,
		"--namespace", namespace,
	}

	cmd := execCommand(s.BinaryPath, args...)
	cmd.Stdin = bytes.NewReader(input)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("kubeseal failed: %v\nStderr: %s", err, stderr.String())
	}

	return stdout.Bytes(), nil
}

// SealRawInto encrypts a single field value and merges it into an existing
// SealedSecret file in place, leaving every other key's ciphertext untouched.
// This is what makes it safe to add a field to a secret that already holds
// generated values: re-running the full seal would hand every generator field a
// fresh random value, silently rotating keys nobody asked to rotate.
//
// The invocation deliberately does NOT use --raw. In kubeseal (verified against
// v0.38.4), --merge-into is dispatched before the --raw branch is ever
// consulted, so combining the two makes --raw a no-op and the --from-file value
// is never read — kubeseal then fails with "no secrets found". --merge-into
// instead expects a complete Secret manifest on stdin and seals it with the
// target file's own name/namespace, so we synthesise a one-key Secret here.
//
// kubeseal reads the existing file only to decode its metadata and merge the
// new ciphertext in; existing values are never decrypted.
func (s *Sealer) SealRawInto(value []byte, namespace, name, field, targetFile string) error {
	if field == "" {
		return fmt.Errorf("field name is required")
	}
	if targetFile == "" {
		return fmt.Errorf("target sealed-secret file is required")
	}

	oneKey := oneKeySecretManifest(value, namespace, name, field)

	args := []string{
		"--format", "yaml",
		"--controller-namespace", s.ControllerNamespace,
		"--scope", "strict",
		"--merge-into", targetFile,
	}

	cmd := execCommand(s.BinaryPath, args...)
	cmd.Stdin = strings.NewReader(oneKey)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("kubeseal --merge-into failed: %v\nStderr: %s", err, stderr.String())
	}
	return nil
}

// oneKeySecretManifest renders a Secret manifest carrying exactly one key.
// The value goes in as base64 under `data` rather than plain `stringData` so
// arbitrary bytes — newlines in a PEM private key, non-UTF-8 — survive the YAML
// round-trip without quoting or indentation games.
func oneKeySecretManifest(value []byte, namespace, name, field string) string {
	return fmt.Sprintf(
		"apiVersion: v1\nkind: Secret\nmetadata:\n  name: %s\n  namespace: %s\ndata:\n  %s: %s\n",
		name, namespace, field, base64.StdEncoding.EncodeToString(value),
	)
}
