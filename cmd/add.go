package cmd

import (
	"fmt"
	"strings"

	"source.example.com/example-org/kryptos/internal/config"
	"source.example.com/example-org/kryptos/internal/kubeseal"
	"source.example.com/example-org/kryptos/internal/secrets"

	"github.com/spf13/cobra"
)

var (
	addValuesFile string
	addSetFlags   []string
	addForce      bool
)

var addCmd = &cobra.Command{
	Use:   "add <app> <secret> <field>",
	Short: "Add a single field to an existing sealed secret without rotating the others",
	Long: `Add encrypts one field's value and merges it into a secret's existing
SealedSecret file, leaving every other key's ciphertext byte-identical.

Use this instead of re-running seal when a secret already exists. Seal
re-resolves every field, so any field with a generator receives a NEW random
value — adding one field by re-sealing silently rotates all the others, and
sealed values cannot be read back to restore them.

The value is resolved in the same precedence order seal uses:

  1. --set field=value (or --set secret.field=value)
  2. --values FILE  (YAML: { "secret.field": v }  or  { field: v })
  3. environment    (KRYPTOS_<SECRET>_<FIELD> or KRYPTOS_<FIELD>)
  4. the field's generator (auto-generated)
  5. the field's static default

The field must already be declared in the config, must not be a derived field,
and must not already be present in the sealed file (pass --force to replace it,
which rotates that key). Honours --dry-run.`,
	Args:          cobra.ExactArgs(3),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(_ *cobra.Command, args []string) error {
		appName, secretName, fieldName := args[0], args[1], args[2]

		layout, err := resolveLayout()
		if err != nil {
			return err
		}

		app, err := loadApp(layout.ConfigDir, appName)
		if err != nil {
			return err
		}

		targets, err := selectSecretsByName(app, []string{secretName}, false)
		if err != nil {
			return err
		}
		secret := targets[0]

		src, err := buildAddValueSource(addValuesFile, addSetFlags, secret.Name, fieldName)
		if err != nil {
			return err
		}

		value, err := resolveSingleValue(src, &secret, fieldName)
		if err != nil {
			return err
		}

		var sealer *kubeseal.Sealer
		if !dryRun {
			sealer, err = kubeseal.NewSealer(layout.ControllerNamespace)
			if err != nil {
				return fmt.Errorf("kubeseal not available: %w", err)
			}
		}

		pipeline := &secrets.Pipeline{Layout: layout, Sealer: sealer, DryRun: dryRun, Hooks: secrets.Hooks{
			EmitDryRun: emitDryRunPlain,
		}}

		res := pipeline.AddField(secrets.AddFieldRequest{
			App:       app,
			Secret:    &secret,
			Field:     fieldName,
			Value:     value,
			Overwrite: addForce,
		})
		if res.Err != nil {
			return fmt.Errorf("%s.%s: %w", secret.Name, fieldName, res.Err)
		}

		fmt.Printf("✓ %s.%s → %s\n", secret.Name, fieldName, res.OutputPath)
		return nil
	},
}

// buildAddValueSource composes the --set / --values / env chain for `add`.
//
// It prepends an exact-match source because `add` knows the one field it is
// targeting, and secret field names routinely contain dots
// (e.g. "omni.client.secret"). The shared qualifiedOrBare helper splits any
// dotted key into "secret.field", so a bare `--set omni.client.secret=x` would
// be filed under the secret named "omni" and never match — the value would be
// silently ignored and a generator field would mint a random value instead.
// Matching the literal field name first makes both --set spellings work.
func buildAddValueSource(valuesFile string, setFlags []string, secretName, fieldName string) (secrets.ValueSource, error) {
	exact := make(map[string]string)

	setMap, err := parseSetFlags(setFlags)
	if err != nil {
		return nil, err
	}
	for _, key := range []string{fieldName, secretName + "." + fieldName} {
		if v, ok := setMap[key]; ok {
			exact[fieldName] = v
		}
	}

	if valuesFile != "" {
		fileMap, err := parseValuesFile(valuesFile)
		if err != nil {
			return nil, err
		}
		if _, taken := exact[fieldName]; !taken {
			for _, key := range []string{fieldName, secretName + "." + fieldName} {
				if v, ok := fileMap[key]; ok {
					exact[fieldName] = v
				}
			}
		}
	}

	chain := secrets.ChainSource{secrets.NewMapSource(nil, exact)}

	// Fall through to the standard sources so env and any other spellings
	// still resolve exactly as they do for `seal`.
	rest, err := buildValueSource(valuesFile, setFlags)
	if err != nil {
		return nil, err
	}
	return append(chain, rest), nil
}

// resolveSingleValue resolves one field's value using the same precedence as
// the non-interactive seal path, without resolving (and thus regenerating) any
// of the secret's other fields — that isolation is the whole point of `add`.
func resolveSingleValue(src secrets.ValueSource, secret *config.Secret, fieldName string) (string, error) {
	var field *config.SecretField
	for i := range secret.Fields {
		if secret.Fields[i].Name == fieldName {
			field = &secret.Fields[i]
			break
		}
	}
	if field == nil {
		// Let AddField produce the canonical "no such field" error, complete
		// with the list of declared fields.
		return "", nil
	}

	// 1. Explicit value from --set / --values / env.
	if v, ok := src.Lookup(secret.Name, field.Name); ok {
		expanded, err := secrets.ExpandMagicKeyword(v, *field)
		if err != nil {
			return "", fmt.Errorf("field %q: %w", field.Name, err)
		}
		return expanded, nil
	}

	// 2. Generator auto-fill.
	if field.Generator != "" {
		gen, err := secrets.GenerateFieldValue(*field)
		if err != nil {
			return "", fmt.Errorf("field %q: %w", field.Name, err)
		}
		return gen, nil
	}

	// 3. Static default.
	if field.Default != "" {
		expanded, err := secrets.ExpandMagicKeyword(field.Default, *field)
		if err != nil {
			return "", fmt.Errorf("field %q: %w", field.Name, err)
		}
		return expanded, nil
	}

	return "", fmt.Errorf(
		"no value for field %q: pass --set %s=... , set it in --values, "+
			"or export KRYPTOS_%s_%s (the field has no generator or default)",
		field.Name, field.Name, envKeyForMsg(secret.Name), envKeyForMsg(field.Name))
}

// envKeyForMsg renders a name the way EnvSource does, so the error message
// names the environment variable the user would actually have to set.
func envKeyForMsg(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

func init() {
	addCmd.Flags().StringVar(&addValuesFile, "values", "",
		"YAML file of values keyed by \"secret.field\" or \"field\"")
	addCmd.Flags().StringArrayVar(&addSetFlags, "set", nil,
		"Set the value: --set field=value or --set secret.field=value")
	addCmd.Flags().BoolVar(&addForce, "force", false,
		"Replace the field if it is already sealed (rotates that key)")
	addCmd.Flags().StringVarP(&configDir, "config-dir", "c", "",
		"Directory containing app config YAML files (default: auto-detected from repo root)")
	addCmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"Print what would be added without sealing or writing files")
	addCmd.Flags().StringVar(&controllerNamespace, "controller-namespace", "",
		"Namespace where the sealed-secrets controller is running")
	rootCmd.AddCommand(addCmd)
}
