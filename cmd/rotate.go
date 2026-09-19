package cmd

import (
	"fmt"

	"source.example.com/example-org/kryptos/internal/kubeseal"
	"source.example.com/example-org/kryptos/internal/secrets"

	"github.com/spf13/cobra"
)

var (
	rotateApp    string
	rotateSecret string
	rotateFields []string
)

var rotateCmd = &cobra.Command{
	Use:   "rotate --app APP --secret SECRET [--field NAME ...]",
	Short: "Regenerate generator field(s), recompute derives, and reseal",
	Long: `Rotate regenerates a secret's generator field(s) with fresh values, re-runs
the derive pipeline so dependent values recompute, and reseals — overwriting
the existing sealed-secret file.

  --field NAME   rotate only this generator field (repeatable). Omit to rotate
                 EVERY generator field in the secret.

Coordinated rotation is free: rotating a password also recomputes its htpasswd
sibling in the same pass. Because sealed values are encrypted at rest, any
non-rotated required field must be supplied with --set/--values (kryptos can't
read the old value back).

Honours --dry-run (prints the new values, never seals/writes).`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if rotateApp == "" || rotateSecret == "" {
			return fmt.Errorf("--app and --secret are required")
		}

		layout, err := resolveLayout()
		if err != nil {
			return err
		}

		app, err := loadApp(layout.ConfigDir, rotateApp)
		if err != nil {
			return err
		}
		targets, err := selectSecretsByName(app, []string{rotateSecret}, false)
		if err != nil {
			return err
		}
		secret := targets[0]

		src, err := buildValueSource(sealValuesFile, sealSetFlags)
		if err != nil {
			return err
		}
		resolver := secrets.RotateResolver(src, rotateFields)

		var sealer *kubeseal.Sealer
		if !dryRun {
			sealer, err = kubeseal.NewSealer(layout.ControllerNamespace)
			if err != nil {
				return fmt.Errorf("kubeseal not available: %w", err)
			}
		}

		// No ConfirmOverwrite hook: rotation overwrites by design.
		pipeline := &secrets.Pipeline{Layout: layout, Sealer: sealer, DryRun: dryRun, Hooks: secrets.Hooks{
			EmitDryRun: emitDryRunPlain,
		}}

		res := pipeline.Process(app, &secret, resolver)
		if res.Err != nil {
			return fmt.Errorf("rotating %s/%s: %w", app.AppName, secret.Name, res.Err)
		}
		if dryRun {
			return nil
		}
		fmt.Printf("✓ rotated %s/%s → %s\n", app.AppName, secret.Name, res.OutputPath)
		return nil
	},
}

func init() {
	rotateCmd.Flags().StringVar(&rotateApp, "app", "", "App whose secret to rotate (required)")
	rotateCmd.Flags().StringVar(&rotateSecret, "secret", "", "Secret to rotate (required)")
	rotateCmd.Flags().StringArrayVar(&rotateFields, "field", nil,
		"Rotate only this generator field (repeatable); omit to rotate all generator fields")
	// Reuse the seal flags for supplying non-rotated values.
	rotateCmd.Flags().StringVar(&sealValuesFile, "values", "",
		"YAML file of values for non-rotated fields (keyed \"secret.field\" or \"field\")")
	rotateCmd.Flags().StringArrayVar(&sealSetFlags, "set", nil,
		"Set a non-rotated value: --set secret.field=value or --set field=value (repeatable)")
	rotateCmd.Flags().StringVarP(&configDir, "config-dir", "c", "",
		"Directory containing app config YAML files (default: auto-detected from repo root)")
	rotateCmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"Print the new values without sealing or writing files")
	rootCmd.AddCommand(rotateCmd)
}
