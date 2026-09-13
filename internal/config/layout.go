package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// Layout resolves where kryptos reads configs from and writes sealed secrets
// to. It decouples the engine from any one repo's directory layout, so the tool
// can be pointed at a different repo via a kryptos.toml.
//
// With no kryptos.toml present, the zero-config defaults match the argo-apps
// directory convention, so a consumer using that layout needs no config.
type Layout struct {
	// RepoRoot is the absolute path the relative settings below resolve against
	// (the directory containing kryptos.toml, or the .git root when defaulting).
	RepoRoot string

	// ConfigDir is the absolute directory holding the app config YAMLs.
	ConfigDir string

	// OutputLayout is a path template, relative to RepoRoot, with {section},
	// {app}, and {name} placeholders, e.g.
	// "cluster/{section}/{app}/secrets/{name}-sealed-secret.yaml".
	OutputLayout string

	// Sections are the {section} candidates tried in order when locating an
	// app's output directory; the first whose app dir exists is used. For
	// argo-apps these are "apps" and "infrastructure".
	Sections []string

	// ControllerNamespace is the default sealed-secrets controller namespace.
	ControllerNamespace string
}

// tomlConfig is the on-disk kryptos.toml shape. All fields are optional;
// anything omitted falls back to the argo-apps default.
type tomlConfig struct {
	ConfigDir           string   `toml:"config_dir"`
	OutputLayout        string   `toml:"output_layout"`
	Sections            []string `toml:"sections"`
	ControllerNamespace string   `toml:"controller_namespace"`
}

const (
	defaultConfigDir           = "tools/kryptos/configs"
	defaultOutputLayout        = "cluster/{section}/{app}/secrets/{name}"
	defaultControllerNamespace = "kube-system"
)

// defaultSections matches the original FindSecretsDir search order.
var defaultSections = []string{"apps", "infrastructure"}

// LoadLayout finds and parses kryptos.toml (searching up from the CWD to the
// .git root), filling any unset field with the argo-apps default. If no
// kryptos.toml exists, it returns a fully-defaulted Layout — identical to the
// pre-decoupling hardcoded behaviour.
func LoadLayout() (*Layout, error) {
	root := findRepoRootFromCWD()

	var tc tomlConfig
	tomlPath := filepath.Join(root, "kryptos.toml")
	if data, err := os.ReadFile(tomlPath); err == nil {
		if err := toml.Unmarshal(data, &tc); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", tomlPath, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading %s: %w", tomlPath, err)
	}

	l := &Layout{
		RepoRoot:            root,
		OutputLayout:        firstNonEmpty(tc.OutputLayout, defaultOutputLayout),
		ControllerNamespace: firstNonEmpty(tc.ControllerNamespace, defaultControllerNamespace),
		Sections:            tc.Sections,
	}
	if len(l.Sections) == 0 {
		l.Sections = defaultSections
	}

	configDir := firstNonEmpty(tc.ConfigDir, defaultConfigDir)
	l.ConfigDir = filepath.Join(root, configDir)

	return l, nil
}

// SecretsDir returns (and creates) the secrets output directory for an app by
// expanding OutputLayout's {section}/{app} for the first section whose app
// directory exists under RepoRoot. The {name} segment is dropped (it's the
// per-file part, added by OutputPath); what remains up to the last path
// separator is the directory.
func (l *Layout) SecretsDir(appName string) (string, error) {
	return l.resolveSecretsDir(appName, true)
}

// SecretsDirReadOnly resolves the secrets directory without creating it — for
// audit/diff and other read-only inspections. Returns an error if no section's
// app directory exists.
func (l *Layout) SecretsDirReadOnly(appName string) (string, error) {
	return l.resolveSecretsDir(appName, false)
}

// resolveSecretsDir finds the secrets directory for an app by trying each
// section in order; the first whose app directory exists wins. When create is
// true the secrets directory is created (MkdirAll) before returning.
func (l *Layout) resolveSecretsDir(appName string, create bool) (string, error) {
	// The directory is the layout up to (but excluding) the {name} filename.
	dirTemplate := filepath.Dir(l.OutputLayout) // e.g. cluster/{section}/{app}/secrets

	var lastTried []string
	for _, section := range l.Sections {
		// The app dir is the layout truncated at {app}: cluster/{section}/{app}.
		appDir := filepath.Join(l.RepoRoot, expandLayout(appDirTemplate(dirTemplate), section, appName, ""))
		lastTried = append(lastTried, appDir)
		if info, err := os.Stat(appDir); err == nil && info.IsDir() {
			secretsDir := filepath.Join(l.RepoRoot, expandLayout(dirTemplate, section, appName, ""))
			if create {
				if err := os.MkdirAll(secretsDir, 0o755); err != nil {
					return "", fmt.Errorf("failed to create secrets directory: %w", err)
				}
			}
			return secretsDir, nil
		}
	}
	return "", fmt.Errorf("could not find application directory for %q (tried: %s)",
		appName, strings.Join(lastTried, ", "))
}

// OutputPath returns the absolute sealed-secret file path for a secret,
// expanding the full OutputLayout (including {name}) and appending the
// "-sealed-secret.yaml" suffix that the {name} placeholder represents. A custom
// secret.Filename overrides the {name} segment entirely.
func (l *Layout) OutputPath(appName string, secret *Secret) (string, error) {
	dir, err := l.SecretsDir(appName)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, SealedFilename(secret)), nil
}

// SealedFilename derives the sealed-secret filename for a secret. A custom
// Filename in the config wins; otherwise a trailing "-secret" is stripped
// before appending "-sealed-secret.yaml" so a name ending in "-secret"
// (e.g. harbor-registry-secret) yields "harbor-registry-sealed-secret.yaml"
// rather than the doubled-up "...-secret-sealed-secret.yaml". This matches the
// convention of every existing sealed-secret file in cluster/.
func SealedFilename(secret *Secret) string {
	if secret.Filename != "" {
		return secret.Filename
	}
	stem := strings.TrimSuffix(secret.Name, "-secret")
	return stem + "-sealed-secret.yaml"
}

// appDirTemplate truncates a directory template at the {app} segment, returning
// the portion up to and including {app} (e.g. "cluster/{section}/{app}/secrets"
// → "cluster/{section}/{app}"). If {app} isn't present, the whole template is
// returned.
func appDirTemplate(dirTemplate string) string {
	parts := strings.Split(dirTemplate, string(filepath.Separator))
	for i, p := range parts {
		if p == "{app}" {
			return filepath.Join(parts[:i+1]...)
		}
	}
	return dirTemplate
}

// expandLayout substitutes the {section}/{app}/{name} placeholders.
func expandLayout(tmpl, section, app, name string) string {
	r := strings.NewReplacer("{section}", section, "{app}", app, "{name}", name)
	return r.Replace(tmpl)
}

// findRepoRootFromCWD walks up from the CWD to the first directory containing a
// .git marker, falling back to the CWD itself if none is found.
func findRepoRootFromCWD() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return mustGetwd()
		}
		dir = parent
	}
}

func mustGetwd() string {
	if d, err := os.Getwd(); err == nil {
		return d
	}
	return "."
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
