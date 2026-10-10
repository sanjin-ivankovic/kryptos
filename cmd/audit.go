package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"source.example.com/example-org/kryptos/internal/config"
	"source.example.com/example-org/kryptos/internal/secrets"

	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Report repo health for kryptos configs and their sealed output",
	Long: `Audit cross-checks every config against the sealed-secret files on disk,
without contacting the cluster, and reports:

  - configs that fail validation
  - config secrets with no corresponding sealed-secret file (never sealed)
  - sealed-secret files in a secrets dir with no backing config (orphaned)

Exit status is non-zero if any problem is found, so audit can gate CI.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		layout, err := resolveLayout()
		if err != nil {
			return err
		}

		files, err := config.ListConfigs(layout.ConfigDir)
		if err != nil {
			return fmt.Errorf("listing configs from %s: %w", layout.ConfigDir, err)
		}
		if len(files) == 0 {
			return fmt.Errorf("no config files found in %s", layout.ConfigDir)
		}

		var problems int
		// Track which sealed files each app's config accounts for, so we can
		// flag orphans (files with no backing config secret).
		for _, f := range files {
			problems += auditConfig(layout, f)
		}

		if problems > 0 {
			return fmt.Errorf("audit found %d problem(s)", problems)
		}
		fmt.Printf("✓ audit clean (%d config(s))\n", len(files))
		return nil
	},
}

// auditConfig audits one config file and returns the number of problems found.
func auditConfig(layout *config.Layout, file string) int {
	app, err := config.LoadConfig(file)
	if err != nil {
		fmt.Printf("✗ %s\n    load error: %v\n", file, err)
		return 1
	}

	problems := 0

	// 1. Validation.
	if verrs := config.Validate(app); len(verrs) > 0 {
		fmt.Printf("✗ %s: %d validation error(s)\n", filepath.Base(file), len(verrs))
		for _, e := range verrs {
			fmt.Printf("    - %v\n", e)
		}
		problems += len(verrs)
	}

	// 2. Resolve the app's secrets dir (read-only). If it doesn't exist yet,
	// every secret is "never sealed".
	secretsDir, dirErr := layout.SecretsDirReadOnly(app.AppName)

	// expected = the sealed filename each config secret maps to.
	expected := make(map[string]bool, len(app.Secrets))
	for i := range app.Secrets {
		secret := app.Secrets[i]
		filename := secrets.SealedFilenameFor(&secret)
		expected[filename] = true

		if dirErr != nil {
			fmt.Printf("✗ %s: secret %q has no sealed output (app dir not found: %v)\n",
				filepath.Base(file), secret.Name, dirErr)
			problems++
			continue
		}
		path := filepath.Join(secretsDir, filename)
		if _, err := os.Stat(path); err != nil {
			fmt.Printf("✗ %s: secret %q has no sealed file (%s)\n",
				filepath.Base(file), secret.Name, filename)
			problems++
		}
	}

	// 3. Orphaned sealed files: *-sealed-secret.yaml in the dir with no backing
	// config secret. Only possible if the dir exists.
	if dirErr == nil {
		for _, orphan := range orphanedSealedFiles(secretsDir, expected) {
			fmt.Printf("✗ %s: orphaned sealed file %q (no backing config secret)\n",
				filepath.Base(file), orphan)
			problems++
		}
	}

	return problems
}

// orphanedSealedFiles returns the *-sealed-secret.yaml files in dir that are not
// in the expected set, sorted.
func orphanedSealedFiles(dir string, expected map[string]bool) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var orphans []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, "-sealed-secret.yaml") {
			continue
		}
		if !expected[name] {
			orphans = append(orphans, name)
		}
	}
	sort.Strings(orphans)
	return orphans
}

func init() {
	auditCmd.Flags().StringVarP(&configDir, "config-dir", "c", "",
		"Directory containing app config YAML files (default: auto-detected from repo root)")
	rootCmd.AddCommand(auditCmd)
}
