package secrets

import (
	"fmt"
	"os"
	"sort"

	"source.example.com/example-org/kryptos/internal/config"
	"source.example.com/example-org/kryptos/internal/generator"

	"github.com/goccy/go-yaml"
)

// sealedSecretFile is the subset of a Bitnami SealedSecret we need to inspect:
// the encryptedData key set (values are ciphertext we can't and don't read).
type sealedSecretFile struct {
	Spec struct {
		EncryptedData map[string]string `yaml:"encryptedData"`
	} `yaml:"spec"`
}

// SealedKeys reads a SealedSecret file and returns its encryptedData key set.
func SealedKeys(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading sealed secret %s: %w", path, err)
	}
	var ss sealedSecretFile
	if err := yaml.Unmarshal(data, &ss); err != nil {
		return nil, fmt.Errorf("parsing sealed secret %s: %w", path, err)
	}
	keys := make([]string, 0, len(ss.Spec.EncryptedData))
	for k := range ss.Spec.EncryptedData {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

// ExpectedKeys returns the data-key set a config secret WOULD produce when
// sealed, computed the same way the seal pipeline does: run the dry-run derive
// pipeline (no cluster) over the field defaults, build the raw Secret, and read
// back its keys. This captures every transform — dropped underscore-internal
// fields, dockerconfigjson's single .dockerconfigjson key, tls/ssh_keypair's
// expanded sibling keys, static stringData — so a structural diff against the
// sealed file is apples-to-apples.
func ExpectedKeys(app *config.AppConfig, secret *config.Secret) ([]string, error) {
	// Seed non-derived fields with a placeholder so required-key validation in
	// GenerateRawSecret passes; the actual values don't matter for the key set.
	data := make(map[string]string)
	for _, f := range secret.Fields {
		if f.Derive != "" {
			continue
		}
		data[f.Name] = "x"
	}

	// dryRun=true so cluster_secret derives don't contact the cluster.
	if err := ApplyDerivedFields(secret, data, true); err != nil {
		return nil, fmt.Errorf("deriving fields: %w", err)
	}
	for k, v := range secret.StringData {
		if _, ok := data[k]; !ok {
			data[k] = v
		}
	}

	raw, err := generator.GenerateRawSecret(app, *secret, data)
	if err != nil {
		return nil, fmt.Errorf("generating secret: %w", err)
	}

	var k8s struct {
		StringData map[string]string `yaml:"stringData"`
		Data       map[string]string `yaml:"data"`
	}
	if err := yaml.Unmarshal(raw, &k8s); err != nil {
		return nil, fmt.Errorf("parsing generated secret: %w", err)
	}

	seen := make(map[string]bool)
	var keys []string
	for k := range k8s.StringData {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for k := range k8s.Data {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// DiffKeys compares two sorted key sets and returns the keys only in expected
// (missing from the sealed file) and only in actual (orphaned in the sealed
// file). Both inputs need not be pre-sorted; the result slices are sorted.
func DiffKeys(expected, actual []string) (missing, orphaned []string) {
	exp := toSet(expected)
	act := toSet(actual)
	for k := range exp {
		if !act[k] {
			missing = append(missing, k)
		}
	}
	for k := range act {
		if !exp[k] {
			orphaned = append(orphaned, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(orphaned)
	return missing, orphaned
}

func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// SealedFilenameFor returns the sealed-secret filename a config secret maps to,
// exposing config.SealedFilename's convention to callers that only have the
// secret (audit/diff). Mirrors the pipeline's output naming.
func SealedFilenameFor(secret *config.Secret) string {
	return config.SealedFilename(secret)
}
