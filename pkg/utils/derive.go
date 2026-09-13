package utils

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"text/template"
)

// execCommand and lookPath are package-level seams so tests can intercept the
// shell-out to kubectl without a real binary or live cluster. Production code
// uses the os/exec implementations; tests swap them for fakes (see
// derive_test.go).
var (
	execCommand = exec.Command
	lookPath    = exec.LookPath
)

// FetchClusterSecret reads a single key out of a Kubernetes Secret in the
// live cluster via kubectl. The caller's current kubeconfig context is used
// — no plumbing, no embedded client-go. Returns the decoded UTF-8 string
// (the secret value as the application sees it, not its base64 form).
//
// Returns an error if kubectl is missing, the user is not authenticated,
// the secret doesn't exist, the key isn't present, or the bytes aren't
// valid UTF-8 (kryptos secrets are always string-typed, so non-UTF-8 is
// almost certainly a misconfiguration worth surfacing).
func FetchClusterSecret(namespace, name, key string) (string, error) {
	if namespace == "" || name == "" || key == "" {
		return "", fmt.Errorf("cluster_secret: namespace, name, and key are all required")
	}

	kubectl, err := lookPath("kubectl")
	if err != nil {
		return "", fmt.Errorf("kubectl binary not found in PATH: %w", err)
	}

	// jsonpath escapes any dots in the key so values like "tls.crt" work.
	jsonpath := fmt.Sprintf(`{.data.%s}`, escapeJSONPathSegment(key))

	cmd := execCommand(kubectl,
		"get", "secret", name,
		"-n", namespace,
		"-o", "jsonpath="+jsonpath,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("kubectl get secret %s/%s failed: %v\n%s",
			namespace, name, err, strings.TrimSpace(stderr.String()))
	}

	encoded := strings.TrimSpace(stdout.String())
	if encoded == "" {
		return "", fmt.Errorf("cluster_secret: key %q not found in secret %s/%s", key, namespace, name)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("cluster_secret: failed to base64-decode value of %s/%s.%s: %w",
			namespace, name, key, err)
	}
	return string(decoded), nil
}

// escapeJSONPathSegment escapes a key for inclusion in a kubectl jsonpath
// expression. JSONPath uses "." as a path separator, so any dots in the
// key itself must be backslash-escaped. Other characters are passed through
// because Kubernetes secret keys are constrained to [-._a-zA-Z0-9].
func escapeJSONPathSegment(key string) string {
	return strings.ReplaceAll(key, ".", `\.`)
}

// RenderTemplate evaluates body as a Go text/template, exposing data
// (sibling field name → value) as the template's "." root context. Uses
// "missingkey=error" so a typo in a {{ .field_name }} reference fails
// loudly rather than rendering "<no value>" silently into a secret.
//
// Whitespace control still works as usual ({{- ... -}}). Functions are
// the default text/template set; we intentionally don't enable Sprig
// here — sealed secret values should be straightforward substitutions,
// not computation.
func RenderTemplate(body string, data map[string]string) (string, error) {
	tmpl, err := template.New("kryptos-derive-render").
		Option("missingkey=error").
		Parse(body)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, data); err != nil {
		return "", fmt.Errorf("render template: %w", err)
	}
	return out.String(), nil
}
