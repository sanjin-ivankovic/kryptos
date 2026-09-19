package cmd

import (
	"fmt"
	"os"
	"strings"

	"source.example.com/example-org/kryptos/internal/config"
	"source.example.com/example-org/kryptos/internal/kubeseal"
	"source.example.com/example-org/kryptos/internal/secrets"

	"github.com/goccy/go-yaml"
	"github.com/spf13/cobra"
)

var (
	sealValuesFile string
	sealSetFlags   []string
	sealAll        bool
	sealForce      bool
)

// refuseReseal is the non-interactive ConfirmReseal hook: it always declines,
// printing which keys the re-seal would have regenerated and pointing at the
// non-destructive alternative. Returning false (rather than erroring inside the
// hook) keeps the Hooks contract intact; Process turns it into a per-secret
// failure that the command reports.
func refuseReseal(w secrets.ResealWarning) bool {
	fmt.Printf("✗ %s already exists (%s)\n", w.Secret, w.Filename)
	if len(w.Regenerated) > 0 {
		fmt.Printf("  re-sealing would REGENERATE, discarding the current values:\n")
		for _, k := range w.Regenerated {
			fmt.Printf("    - %s\n", k)
		}
	}
	if len(w.Preserved) > 0 {
		fmt.Printf("  preserved: %s\n", strings.Join(w.Preserved, ", "))
	}
	fmt.Printf("  to add a single field without touching the rest:\n")
	fmt.Printf("    kryptos add %s %s <field>\n", w.App, w.Secret)
	fmt.Printf("  to re-seal anyway (rotates the keys listed above): --force\n")
	return false
}

var sealCmd = &cobra.Command{
	Use:   "seal <app> [secret...]",
	Short: "Non-interactively generate and seal secrets (CI-friendly)",
	Long: `Seal generates and seals one or more of an app's secrets without the TUI,
resolving each non-derived field's value in precedence order:

  1. --set secret.field=value (repeatable) or --set field=value
  2. --values FILE  (YAML: { "secret.field": v }  or  { field: v })
  3. environment    (KRYPTOS_<SECRET>_<FIELD> or KRYPTOS_<FIELD>)
  4. the field's generator (auto-generated)
  5. the field's static default

A required field with none of the above is a hard error. Derived fields
(htpasswd/cluster_secret/render/tls/...) are computed exactly as in the
interactive path, so the sealed output is identical for the same inputs.

Name the secrets to seal, or pass --all to seal every secret in the app.
Honours --dry-run (prints, never seals/writes; no cluster needed).

If a secret's sealed file already exists, seal refuses and lists the keys a
re-seal would regenerate: every generator field gets a new random value, and
the old one cannot be read back out of the sealed file. Use "kryptos add" to
add one field without touching the rest, or --force to re-seal anyway.`,
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(_ *cobra.Command, args []string) error {
		layout, err := resolveLayout()
		if err != nil {
			return err
		}

		appName := args[0]
		secretNames := args[1:]
		if len(secretNames) == 0 && !sealAll {
			return fmt.Errorf("name at least one secret to seal, or pass --all")
		}

		app, err := loadApp(layout.ConfigDir, appName)
		if err != nil {
			return err
		}

		targets, err := selectSecretsByName(app, secretNames, sealAll)
		if err != nil {
			return err
		}

		src, err := buildValueSource(sealValuesFile, sealSetFlags)
		if err != nil {
			return err
		}
		resolver := secrets.NonInteractiveResolver(src)

		var sealer *kubeseal.Sealer
		if !dryRun {
			sealer, err = kubeseal.NewSealer(layout.ControllerNamespace)
			if err != nil {
				return fmt.Errorf("kubeseal not available: %w", err)
			}
		}

		hooks := secrets.Hooks{EmitDryRun: emitDryRunPlain}
		if !sealForce {
			// Re-sealing an existing secret rotates every generator field in
			// it. Without --force, refuse and name the safe alternative rather
			// than destroying values that cannot be read back.
			hooks.ConfirmReseal = refuseReseal
		}

		pipeline := &secrets.Pipeline{Layout: layout, Sealer: sealer, DryRun: dryRun, Hooks: hooks}

		failed := 0
		for i := range targets {
			secret := targets[i]
			res := pipeline.Process(app, &secret, resolver)
			if res.Err != nil {
				failed++
				fmt.Printf("✗ %s: %v\n", secret.Name, res.Err)
				continue
			}
			fmt.Printf("✓ %s → %s\n", secret.Name, res.OutputPath)
		}
		if failed > 0 {
			return fmt.Errorf("%d of %d secret(s) failed", failed, len(targets))
		}
		return nil
	},
}

// loadApp loads the config for a single app by name from dir.
func loadApp(dir, appName string) (*config.AppConfig, error) {
	files, err := config.ListConfigs(dir)
	if err != nil {
		return nil, fmt.Errorf("listing configs from %s: %w", dir, err)
	}
	for _, f := range files {
		app, err := config.LoadConfig(f)
		if err != nil {
			continue
		}
		if app.AppName == appName {
			return app, nil
		}
	}
	return nil, fmt.Errorf("no config found for app %q in %s", appName, dir)
}

// selectSecretsByName returns the requested secrets (or all when all is true),
// erroring on any name that doesn't exist in the app.
func selectSecretsByName(app *config.AppConfig, names []string, all bool) ([]config.Secret, error) {
	if all {
		if len(app.Secrets) == 0 {
			return nil, fmt.Errorf("app %q has no secrets", app.AppName)
		}
		return app.Secrets, nil
	}
	byName := make(map[string]config.Secret, len(app.Secrets))
	for _, s := range app.Secrets {
		byName[s.Name] = s
	}
	var out []config.Secret
	for _, n := range names {
		s, ok := byName[n]
		if !ok {
			return nil, fmt.Errorf("app %q has no secret named %q", app.AppName, n)
		}
		out = append(out, s)
	}
	return out, nil
}

// buildValueSource composes the --set, --values, and environment sources in
// precedence order (--set wins, then --values, then env).
func buildValueSource(valuesFile string, setFlags []string) (secrets.ValueSource, error) {
	var chain secrets.ChainSource

	if len(setFlags) > 0 {
		setMap, err := parseSetFlags(setFlags)
		if err != nil {
			return nil, err
		}
		chain = append(chain, qualifiedOrBare(setMap))
	}

	if valuesFile != "" {
		fileMap, err := parseValuesFile(valuesFile)
		if err != nil {
			return nil, err
		}
		chain = append(chain, qualifiedOrBare(fileMap))
	}

	chain = append(chain, secrets.EnvSource{Getenv: os.Getenv})
	return chain, nil
}

// qualifiedOrBare splits a flat string map into qualified ("secret.field") and
// bare ("field") entries and wraps them in a MapSource.
//
// A dotted key is registered as BOTH, because field names themselves routinely
// contain dots — "jwks.rsa.key", "storage.encryption.key",
// "omni.client.secret". Treating a dotted key as qualified only would file
// `--set jwks.rsa.key=x` under a secret named "jwks", where it never matches;
// the value would be silently dropped and a generator field would mint a random
// value in its place. Registering both spellings makes the literal field name
// win when no such secret exists, and a genuine "secret.field" qualifier still
// takes precedence via MapSource's lookup order.
func qualifiedOrBare(m map[string]string) *secrets.MapSource {
	qualified := make(map[string]string)
	bare := make(map[string]string)
	for k, v := range m {
		if strings.Contains(k, ".") {
			qualified[k] = v
			bare[k] = v
		} else {
			bare[k] = v
		}
	}
	return secrets.NewMapSource(qualified, bare)
}

// parseSetFlags parses repeated --set key=value flags into a map.
func parseSetFlags(flags []string) (map[string]string, error) {
	out := make(map[string]string, len(flags))
	for _, f := range flags {
		k, v, ok := strings.Cut(f, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid --set %q (want key=value)", f)
		}
		out[k] = v
	}
	return out, nil
}

// parseValuesFile reads a YAML file of string→string (or string→scalar) values.
func parseValuesFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading values file %s: %w", path, err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing values file %s: %w", path, err)
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		out[k] = fmt.Sprintf("%v", v)
	}
	return out, nil
}

func init() {
	sealCmd.Flags().StringVar(&sealValuesFile, "values", "",
		"YAML file of values keyed by \"secret.field\" or \"field\"")
	sealCmd.Flags().StringArrayVar(&sealSetFlags, "set", nil,
		"Set a value: --set secret.field=value or --set field=value (repeatable)")
	sealCmd.Flags().BoolVar(&sealAll, "all", false, "Seal every secret in the app")
	sealCmd.Flags().BoolVar(&sealForce, "force", false,
		"Re-seal secrets whose sealed file already exists, regenerating their generator fields")
	sealCmd.Flags().StringVarP(&configDir, "config-dir", "c", "",
		"Directory containing app config YAML files (default: auto-detected from repo root)")
	sealCmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"Print what would be generated without sealing or writing files")
	rootCmd.AddCommand(sealCmd)
}
