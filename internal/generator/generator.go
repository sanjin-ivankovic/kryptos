package generator

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"source.example.com/example-org/kryptos/internal/config"

	"github.com/goccy/go-yaml"
)

// K8sSecret represents a standard Kubernetes Secret
type K8sSecret struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   Metadata          `yaml:"metadata"`
	Type       string            `yaml:"type"`
	StringData map[string]string `yaml:"stringData,omitempty"`
	Data       map[string]string `yaml:"data,omitempty"`
}

type Metadata struct {
	Name        string            `yaml:"name"`
	Namespace   string            `yaml:"namespace"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

// dockerConfigJSON represents the structure of .dockerconfigjson
type dockerConfigJSON struct {
	Auths map[string]dockerAuthEntry `json:"auths"`
}

type dockerAuthEntry struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Auth     string `json:"auth"`
}

// generateDockerConfigJSON creates a Docker config JSON from username, password, email, and server
func generateDockerConfigJSON(data map[string]string) (string, error) {
	username, ok := data["username"]
	if !ok || username == "" {
		return "", fmt.Errorf("missing required field: username")
	}

	password, ok := data["password"]
	if !ok || password == "" {
		return "", fmt.Errorf("missing required field: password")
	}

	email := data["email"] // optional

	server, ok := data["server"]
	if !ok || server == "" {
		server = "https://index.docker.io/v1/" // Default to Docker Hub
	}

	// Create the auth string (base64 encoded "username:password")
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	config := dockerConfigJSON{
		Auths: map[string]dockerAuthEntry{
			server: {
				Username: username,
				Password: password,
				Email:    email,
				Auth:     auth,
			},
		},
	}

	jsonBytes, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("error marshaling docker config: %w", err)
	}

	return string(jsonBytes), nil
}

// GenerateRawSecret creates a Kubernetes Secret struct populated with data.
//
// Fields whose name begins with "_" are considered INTERNAL to the secret's
// derivation pipeline (e.g. a value pulled from another cluster Secret and
// referenced inside a `derive: render` template) and are dropped from the
// final Secret. This lets a config compose a result from intermediate
// inputs without exposing the inputs themselves as separate secret keys.
func GenerateRawSecret(cfg *config.AppConfig, secretCfg config.Secret, data map[string]string) ([]byte, error) {
	// Validate required keys
	for _, field := range secretCfg.Fields {
		// Checks if the key is required
		if field.Required {
			if _, ok := data[field.Name]; !ok {
				// Check if it's in static StringData
				if _, okStr := secretCfg.StringData[field.Name]; !okStr {
					return nil, fmt.Errorf("missing required key: %s", field.Name)
				}
			}
		}
	}

	// Build the secret's stringData, dropping internal (underscore-prefixed)
	// fields so they don't end up as separate keys in the final Secret.
	stringData := make(map[string]string, len(data))
	for k, v := range data {
		if strings.HasPrefix(k, "_") {
			continue
		}
		stringData[k] = v
	}

	// Determine secret type (default to Opaque if not specified)
	secretType := "Opaque"
	if secretCfg.Type != "" {
		secretType = secretCfg.Type
	}

	secret := K8sSecret{
		APIVersion: "v1",
		Kind:       "Secret",
		Metadata: Metadata{
			Name:        secretCfg.Name,
			Namespace:   cfg.Namespace,
			Labels:      secretCfg.Labels,
			Annotations: secretCfg.Annotations,
		},
		Type:       secretType,
		StringData: stringData,
	}

	// Special handling for Docker registry secrets
	if secretType == "kubernetes.io/dockerconfigjson" {
		dockerConfig, err := generateDockerConfigJSON(data)
		if err != nil {
			return nil, fmt.Errorf("error generating docker config: %w", err)
		}
		secret.StringData = map[string]string{
			".dockerconfigjson": dockerConfig,
		}
	} else {
		// Add any static StringData from config for non-docker secrets
		for k, v := range secretCfg.StringData {
			if secret.StringData == nil {
				secret.StringData = make(map[string]string)
			}
			secret.StringData[k] = v
		}
	}

	return yaml.Marshal(secret)
}
