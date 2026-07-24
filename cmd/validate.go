package cmd

import (
	"fmt"

	"source.example.com/example-org/kryptos/internal/config"

	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate all kryptos config files without contacting the cluster",
	Long: `Validate loads every config in the config directory and checks it for the
problems that would make secret generation fail: malformed names, duplicate
keys, unknown generators or derive types, and broken derive references
(htpasswd/cluster_secret/render). It needs no cluster access, so it is safe to
run in CI and pre-commit.

Exit status is non-zero if any config fails to load or fails validation.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		layout, err := resolveLayout()
		if err != nil {
			return err
		}
		dir := layout.ConfigDir

		files, err := config.ListConfigs(dir)
		if err != nil {
			return fmt.Errorf("listing configs from %s: %w", dir, err)
		}
		if len(files) == 0 {
			return fmt.Errorf("no config files found in %s", dir)
		}

		total := 0
		failed := 0
		for _, f := range files {
			total++
			app, err := config.LoadConfig(f)
			if err != nil {
				// Unlike the interactive root command, validate treats an
				// unparseable config as a hard failure.
				failed++
				fmt.Printf("✗ %s\n    load error: %v\n", f, err)
				continue
			}
			problems := config.Validate(app)
			if len(problems) == 0 {
				logger.Debug("config valid", "file", f)
				continue
			}
			failed++
			fmt.Printf("✗ %s\n", f)
			for _, p := range problems {
				fmt.Printf("    - %v\n", p)
			}
		}

		if failed > 0 {
			return fmt.Errorf("%d of %d config(s) failed validation", failed, total)
		}
		fmt.Printf("✓ all %d config(s) valid\n", total)
		return nil
	},
}

func init() {
	// Reuse the root --config-dir flag so `kryptos validate -c <dir>` works.
	validateCmd.Flags().StringVarP(&configDir, "config-dir", "c", "",
		"Directory containing app config YAML files (default: auto-detected from repo root)")
	rootCmd.AddCommand(validateCmd)
}
