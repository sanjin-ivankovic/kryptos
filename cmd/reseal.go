package cmd

import (
	"fmt"
	"os"

	"source.example.com/example-org/kryptos/internal/config"
	"source.example.com/example-org/kryptos/internal/kubeseal"
	"source.example.com/example-org/kryptos/internal/secrets"

	"github.com/spf13/cobra"
)

var resealAll bool

var resealCmd = &cobra.Command{
	Use:   "reseal [app...]",
	Short: "Re-encrypt sealed secrets under the controller's newest key",
	Long: `Reseal re-encrypts existing sealed-secret files with kubeseal --re-encrypt.
The controller decrypts each one with whichever key sealed it and encrypts it
again under its newest key, so every value stays the same and no plaintext
leaves the cluster. Use it after the controller renews its sealing key, or to
retire old keys.

Name the apps, or pass --all for every app with a config. A secret without a
sealed file is skipped. A file is replaced only when the result keeps its name,
namespace and key set.

Honours --dry-run (lists the files, no cluster needed).`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(_ *cobra.Command, args []string) error {
		if len(args) == 0 && !resealAll {
			return fmt.Errorf("name at least one app, or pass --all")
		}
		layout, err := resolveLayout()
		if err != nil {
			return err
		}
		apps, err := resealApps(layout.ConfigDir, args)
		if err != nil {
			return err
		}

		var reEncrypt secrets.ReEncrypter
		if !dryRun {
			sealer, err := kubeseal.NewSealer(layout.ControllerNamespace)
			if err != nil {
				return fmt.Errorf("kubeseal not available: %w", err)
			}
			reEncrypt = sealer.ReEncrypt
		}

		done, failed := 0, 0
		for _, app := range apps {
			for i := range app.Secrets {
				secret := &app.Secrets[i]
				path, err := layout.OutputPath(app.AppName, secret)
				if err != nil {
					continue
				}
				if _, err := os.Stat(path); err != nil {
					continue
				}
				if dryRun {
					fmt.Printf("would re-encrypt %s/%s → %s\n", app.AppName, secret.Name, path)
					done++
					continue
				}
				if err := secrets.ResealFile(path, reEncrypt); err != nil {
					failed++
					fmt.Printf("✗ %s/%s: %v\n", app.AppName, secret.Name, err)
					continue
				}
				done++
				fmt.Printf("✓ %s/%s → %s\n", app.AppName, secret.Name, path)
			}
		}
		if failed > 0 {
			return fmt.Errorf("%d of %d sealed file(s) failed", failed, done+failed)
		}
		if dryRun {
			fmt.Printf("%d sealed file(s) would be re-encrypted\n", done)
		} else {
			fmt.Printf("%d sealed file(s) re-encrypted\n", done)
		}
		return nil
	},
}

// resealApps loads the named apps, or every app with a config when none are named.
func resealApps(dir string, names []string) ([]*config.AppConfig, error) {
	if len(names) > 0 {
		out := make([]*config.AppConfig, 0, len(names))
		for _, n := range names {
			app, err := loadApp(dir, n)
			if err != nil {
				return nil, err
			}
			out = append(out, app)
		}
		return out, nil
	}
	files, err := config.ListConfigs(dir)
	if err != nil {
		return nil, fmt.Errorf("listing configs from %s: %w", dir, err)
	}
	out := make([]*config.AppConfig, 0, len(files))
	for _, f := range files {
		app, err := config.LoadConfig(f)
		if err != nil {
			return nil, fmt.Errorf("loading %s: %w", f, err)
		}
		out = append(out, app)
	}
	return out, nil
}

func init() {
	resealCmd.Flags().BoolVar(&resealAll, "all", false, "Re-encrypt every app's sealed files")
	resealCmd.Flags().StringVarP(&configDir, "config-dir", "c", "",
		"Directory containing app config YAML files (default: auto-detected from repo root)")
	resealCmd.Flags().BoolVar(&dryRun, "dry-run", false, "List the files without contacting the cluster")
	rootCmd.AddCommand(resealCmd)
}
