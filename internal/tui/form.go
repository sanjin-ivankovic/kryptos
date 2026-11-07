package tui

import (
	"fmt"
	"strings"

	huh "charm.land/huh/v2"

	"source.example.com/example-org/kryptos/internal/config"
	"source.example.com/example-org/kryptos/internal/secrets"
)

// runSecretForm builds a dynamic huh form from the secret definition and runs it.
// pregenValues holds auto-generated defaults that the user can review or change.
func runSecretForm(secret *config.Secret, pregenValues map[string]string) (map[string]string, error) {
	values := make([]string, len(secret.Fields))
	for i, field := range secret.Fields {
		if v, ok := pregenValues[field.Name]; ok {
			values[i] = v
		} else if field.Default != "" {
			values[i] = field.Default
		}
	}

	fields := make([]huh.Field, 0, len(secret.Fields))
	for i, field := range secret.Fields {
		// Derived fields are computed after the form returns; don't prompt for them.
		if field.Derive != "" {
			continue
		}
		prompt := field.Prompt
		if prompt == "" {
			prompt = field.Name
		}
		help := field.Help
		if help == "" && pregenValues[field.Name] != "" {
			help = "Auto-generated — edit to override, or clear and type a magic keyword: secure · strong · apikey · passphrase"
		}

		idx := i // capture for closure
		if field.Multiline {
			f := huh.NewText().
				Title(prompt).
				Key(field.Name).
				Value(&values[idx])
			if help != "" {
				f = f.Description(help)
			}
			fields = append(fields, f)
		} else {
			f := huh.NewInput().
				Title(prompt).
				Key(field.Name).
				Value(&values[idx])
			if help != "" {
				f = f.Description(help)
			}
			// Default policy: every field in a kryptos config produces a
			// value that lands inside a sealed Secret, so we mask by
			// default. The previous substring-heuristic missed fields
			// like CSRF_KEY and apikey-style keys, leaking their values
			// to the operator's screen. Opt OUT per-field with
			// `sensitive: false` in the config when the value is
			// genuinely non-secret (e.g. a username, hostname, or
			// database name with a default).
			if fieldIsMasked(field) {
				f = f.EchoMode(huh.EchoModePassword)
			}
			if field.Required {
				captured := prompt
				f = f.Validate(func(v string) error {
					if strings.TrimSpace(v) == "" {
						return fmt.Errorf("%s is required", captured)
					}
					return nil
				})
			}
			fields = append(fields, f)
		}
	}

	title := secret.DisplayName
	if title == "" {
		title = secret.Name
	}

	// If every field in this secret is derived (no interactive input),
	// skip the huh form entirely. huh.NewGroup panics on an empty fields
	// slice (charm.land/huh/v2 group.go selector.Selected indexes into a
	// zero-length list). The derive pipeline runs afterwards in
	// applyDerivedFields and populates everything.
	if len(fields) == 0 {
		return make(map[string]string, len(secret.Fields)), nil
	}

	group := huh.NewGroup(fields...).Title(title)
	if secret.Description != "" {
		group = group.Description(secret.Description)
	}

	if err := huh.NewForm(group).Run(); err != nil {
		return nil, err
	}

	// Collect results and expand any magic keywords the user may have typed.
	// Derived fields are skipped here — the pipeline's ApplyDerivedFields
	// populates them from sibling values after this function returns.
	result := make(map[string]string, len(secret.Fields))
	for i, field := range secret.Fields {
		if field.Derive != "" {
			continue
		}
		expanded, err := secrets.ExpandMagicKeyword(values[i], field)
		if err != nil {
			return nil, fmt.Errorf("expanding keyword for %s: %w", field.Name, err)
		}
		result[field.Name] = expanded
	}
	return result, nil
}

// fieldIsMasked reports whether a field's input should be echoed as a password.
// The default is to mask; only an explicit `sensitive: false` opts out. Shared
// with the dry-run output so the form and the dry-run agree on what's secret.
func fieldIsMasked(field config.SecretField) bool {
	return field.Sensitive == nil || *field.Sensitive
}
