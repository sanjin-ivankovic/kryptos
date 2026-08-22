package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
)

// Internal definitions (Used by the application)

type AppConfig struct {
	AppName     string
	DisplayName string
	Namespace   string
	Secrets     []Secret
}

type Secret struct {
	Name        string
	DisplayName string
	Type        string
	Description string
	Filename    string
	Fields      []SecretField // Unified list of fields
	Labels      map[string]string
	Annotations map[string]string
	StringData  map[string]string
}

type SecretField struct {
	Name      string
	Prompt    string
	Help      string
	Required  bool
	Generator string
	Default   string
	Length    int
	Multiline bool

	// Sensitive controls whether the TUI masks this field's input. The
	// default policy (when nil/unset) is to mask EVERYTHING — every field
	// in a kryptos config produces a value that ends up in a sealed Secret,
	// so the safe default is "this is a secret". Set explicitly to `false`
	// for fields where masking hurts UX (e.g. database usernames, hostnames,
	// or other display-only values) and where the value is not sensitive.
	Sensitive *bool

	// Derive marks this field as computed from another field, a cluster
	// resource, or a template rather than prompted for. Supported values:
	//
	//   htpasswd        — produces "<DeriveUsername>:<bcrypt(value of DeriveFrom)>"
	//                     Requires DeriveFrom + DeriveUsername.
	//
	//   cluster_secret  — reads a key from a live cluster Secret at seal
	//                     time, so callers don't have to re-paste a secret
	//                     value that's already in the cluster. Requires
	//                     DeriveNamespace + DeriveSecret + DeriveKey.
	//
	//   render          — renders DeriveTemplate as a Go text/template,
	//                     with sibling field values available as
	//                     {{ .field_name }}. Use for config-file blobs
	//                     that need a templated password baked in.
	//
	// Derived fields are hidden from the input form. The computation runs
	// after the form returns but before the secret is sealed.
	//
	// Field names beginning with "_" are treated as INTERNAL inputs for
	// other derive computations and are NOT written into the final
	// Secret's data — useful for "fetch a value from the cluster to feed
	// it into a render template" without leaking the raw fetched value as
	// a separate secret key.
	Derive          string
	DeriveFrom      string // sibling field name whose value feeds the derivation (htpasswd)
	DeriveUsername  string // username component, only used by "htpasswd"
	DeriveNamespace string // source namespace, only used by "cluster_secret"
	DeriveSecret    string // source secret name, only used by "cluster_secret"
	DeriveKey       string // source secret data key, only used by "cluster_secret"
	DeriveTemplate  string // Go text/template body, only used by "render"

	// Additional derive inputs (Phase 2 derive types).
	DeriveCommonName string   // X.509 CN, only used by "tls" (defaults to the field name)
	DeriveHosts      []string // SAN DNS names / IPs, only used by "tls"
	DeriveComment    string   // SSH public-key comment, only used by "ssh_keypair"
	DerivePath       string   // path to read, only used by "file"
}

// V1 Schema Definitions

type kv1AppConfig struct {
	APIVersion string      `yaml:"apiVersion"`
	Kind       string      `yaml:"kind"`
	Metadata   kv1Metadata `yaml:"metadata"`
	Spec       kv1Spec     `yaml:"spec"`
}

type kv1Metadata struct {
	Name        string `yaml:"name"`
	DisplayName string `yaml:"displayName"`
	Namespace   string `yaml:"namespace"`
}

type kv1Spec struct {
	Secrets []kv1Secret `yaml:"secrets"`
}

type kv1Secret struct {
	Name        string            `yaml:"name"`
	DisplayName string            `yaml:"displayName"`
	Description string            `yaml:"description"`
	Type        string            `yaml:"type"`
	Filename    string            `yaml:"filename"`
	Fields      []kv1Field        `yaml:"fields"`
	StringData  map[string]string `yaml:"stringData"`
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
}

type kv1Field struct {
	Name      string `yaml:"name"`
	Prompt    string `yaml:"prompt"`
	Help      string `yaml:"help"`
	Required  bool   `yaml:"required"`
	Generator string `yaml:"generator"`
	Default   string `yaml:"default"`
	Length    int    `yaml:"length"`
	Multiline bool   `yaml:"multiline"`

	// Pointer so we can tell "absent" apart from "explicitly false".
	// nil → use the workflow default (mask), false → render in plaintext.
	Sensitive *bool `yaml:"sensitive,omitempty"`

	Derive          string `yaml:"derive"`
	DeriveFrom      string `yaml:"derive_from"`
	DeriveUsername  string `yaml:"derive_username"`
	DeriveNamespace string `yaml:"derive_namespace"`
	DeriveSecret    string `yaml:"derive_secret"`
	DeriveKey       string `yaml:"derive_key"`
	DeriveTemplate  string `yaml:"derive_template"`

	// Additional derive inputs (Phase 2 derive types). Field order MUST match
	// SecretField so the SecretField(f) conversion in loadV1Config stays valid.
	DeriveCommonName string   `yaml:"derive_common_name"`
	DeriveHosts      []string `yaml:"derive_hosts"`
	DeriveComment    string   `yaml:"derive_comment"`
	DerivePath       string   `yaml:"derive_path"`
}

// Legacy Schema Definitions

type legacyAppConfig struct {
	AppName     string         `yaml:"app_name"`
	DisplayName string         `yaml:"display_name"`
	Namespace   string         `yaml:"namespace"`
	Secrets     []legacySecret `yaml:"secrets"`
}

type legacySecret struct {
	Name        string            `yaml:"name"`
	DisplayName string            `yaml:"display_name"`
	Type        string            `yaml:"type"`
	Description string            `yaml:"description"`
	Keys        []string          `yaml:"keys"`
	StringData  map[string]string `yaml:"stringData"`
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
}

// LoadConfig reads a YAML configuration file and returns a unified AppConfig
func LoadConfig(path string) (*AppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	// 1. Try mapping the API Version
	var header struct {
		APIVersion string `yaml:"apiVersion"`
	}
	if err := yaml.Unmarshal(data, &header); err == nil && header.APIVersion == "kryptos.dev/v1" {
		return loadV1Config(data)
	}

	// 2. Fallback to Legacy
	return loadLegacyConfig(data)
}

func loadV1Config(data []byte) (*AppConfig, error) {
	var v1 kv1AppConfig
	if err := yaml.Unmarshal(data, &v1); err != nil {
		return nil, fmt.Errorf("error parsing v1 config: %w", err)
	}

	app := &AppConfig{
		AppName:     v1.Metadata.Name,
		DisplayName: v1.Metadata.DisplayName,
		Namespace:   v1.Metadata.Namespace,
	}

	for _, s := range v1.Spec.Secrets {
		secret := Secret{
			Name:        s.Name,
			DisplayName: s.DisplayName,
			Type:        s.Type,
			Description: s.Description,
			Filename:    s.Filename,
			Labels:      s.Labels,
			Annotations: s.Annotations,
			StringData:  s.StringData,
		}
		for _, f := range s.Fields {
			// kv1Field and SecretField share an identical field layout (kv1Field
			// only adds yaml tags, which a conversion ignores), so a direct
			// conversion is exact and avoids 16 lines of field-by-field copying.
			secret.Fields = append(secret.Fields, SecretField(f))
		}
		app.Secrets = append(app.Secrets, secret)
	}
	return app, nil
}

func loadLegacyConfig(data []byte) (*AppConfig, error) {
	var legacy legacyAppConfig
	if err := yaml.Unmarshal(data, &legacy); err != nil {
		return nil, fmt.Errorf("error parsing legacy config: %w", err)
	}

	app := &AppConfig{
		AppName:     legacy.AppName,
		DisplayName: legacy.DisplayName,
		Namespace:   legacy.Namespace,
	}

	for _, s := range legacy.Secrets {
		secret := Secret{
			Name:        s.Name,
			DisplayName: s.DisplayName,
			Type:        s.Type,
			Description: s.Description,
			Labels:      s.Labels,
			Annotations: s.Annotations,
			StringData:  s.StringData,
		}
		// Convert string keys to Fields
		for _, k := range s.Keys {
			secret.Fields = append(secret.Fields, SecretField{
				Name:   k,
				Prompt: k, // Default prompt is the key name
			})
		}
		app.Secrets = append(app.Secrets, secret)
	}
	return app, nil
}

// ListConfigs finds all YAML configs in the given directory
func ListConfigs(dir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	return files, nil
}
