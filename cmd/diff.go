package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"source.example.com/example-org/kryptos/internal/config"
	"source.example.com/example-org/kryptos/internal/secrets"

	"github.com/spf13/cobra"
)

var diffCmd = &cobra.Command{
	Use:   "diff [app]",
	Short: "Show structural drift between configs and their sealed-secret files",
	Long: `Diff compares, per secret, the data-key SET a config would produce against
the keys present in its sealed-secret file's spec.encryptedData. Sealed values
are encrypted by design, so this is a STRUCTURAL diff (which keys differ), not a
value diff.

  + key   the config defines a key the sealed file is missing (reseal needed)
  - key   the sealed file has a key the config no longer defines (orphaned)

With no argument, every app is diffed. Pass an app name to diff just one.
Exit status is non-zero if any drift is found, so diff can gate CI.`,
	Args:          cobra.MaximumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(_ *cobra.Command, args []string) error {
		layout, err := resolveLayout()
		if err != nil {
			return err
		}

		files, err := config.ListConfigs(layout.ConfigDir)
		if err != nil {
			return fmt.Errorf("listing configs from %s: %w", layout.ConfigDir, err)
		}

		var wantApp string
		if len(args) == 1 {
			wantApp = args[0]
		}

		drift := 0
		matched := false
		for _, f := range files {
			app, err := config.LoadConfig(f)
			if err != nil {
				fmt.Printf("✗ %s: load error: %v\n", filepath.Base(f), err)
				drift++
				continue
			}
			if wantApp != "" && app.AppName != wantApp {
				continue
			}
			matched = true
			drift += diffApp(layout, app)
		}

		if wantApp != "" && !matched {
			return fmt.Errorf("no config found for app %q", wantApp)
		}
		if drift > 0 {
			return fmt.Errorf("found structural drift in %d secret(s)", drift)
		}
		fmt.Println("✓ no structural drift")
		return nil
	},
}

// diffApp diffs every secret in an app and returns the count of secrets with
// drift (or unreadable/absent sealed files).
func diffApp(layout *config.Layout, app *config.AppConfig) int {
	secretsDir, err := layout.SecretsDirReadOnly(app.AppName)
	if err != nil {
		fmt.Printf("✗ %s: %v\n", app.AppName, err)
		return len(app.Secrets)
	}

	drift := 0
	for i := range app.Secrets {
		secret := app.Secrets[i]
		path := filepath.Join(secretsDir, secrets.SealedFilenameFor(&secret))

		if _, statErr := os.Stat(path); statErr != nil {
			fmt.Printf("✗ %s/%s: no sealed file (%s)\n",
				app.AppName, secret.Name, filepath.Base(path))
			drift++
			continue
		}

		expected, err := secrets.ExpectedKeys(app, &secret)
		if err != nil {
			fmt.Printf("✗ %s/%s: computing expected keys: %v\n", app.AppName, secret.Name, err)
			drift++
			continue
		}
		actual, err := secrets.SealedKeys(path)
		if err != nil {
			fmt.Printf("✗ %s/%s: %v\n", app.AppName, secret.Name, err)
			drift++
			continue
		}

		missing, orphaned := secrets.DiffKeys(expected, actual)
		if len(missing) == 0 && len(orphaned) == 0 {
			continue
		}
		drift++
		fmt.Printf("~ %s/%s\n", app.AppName, secret.Name)
		for _, k := range missing {
			fmt.Printf("    + %s\n", k)
		}
		for _, k := range orphaned {
			fmt.Printf("    - %s\n", k)
		}
	}
	return drift
}

func init() {
	diffCmd.Flags().StringVarP(&configDir, "config-dir", "c", "",
		"Directory containing app config YAML files (default: auto-detected from repo root)")
	rootCmd.AddCommand(diffCmd)
}
