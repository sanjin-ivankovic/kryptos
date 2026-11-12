package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"source.example.com/example-org/kryptos/internal/secrets"

	"github.com/spf13/cobra"
)

var statusOutput string

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Report every config and sealed file in one pass (text or JSON)",
	Long: `Status runs the checks of validate, audit and diff in one pass over the
repo and reports them together: configs that fail to load or validate,
secrets with no sealed file, keys the sealed file lacks or no longer needs,
sealed files no config accounts for, and the immutable fields of each secret.
It reads only the repo, never the cluster.

--output json prints one JSON document for tools (the homelab drift report).
Exit status is non-zero when any problem is found, in both formats.`,
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if statusOutput != "text" && statusOutput != "json" {
			return fmt.Errorf("--output must be text or json, not %q", statusOutput)
		}
		layout, err := resolveLayout()
		if err != nil {
			return err
		}
		st, err := secrets.BuildStatus(layout)
		if err != nil {
			return err
		}
		if statusOutput == "json" {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(st); err != nil {
				return err
			}
		} else {
			printStatus(st)
		}
		if !st.OK {
			return fmt.Errorf("%d problem(s)", st.Problems)
		}
		return nil
	},
}

func printStatus(st *secrets.Status) {
	for _, p := range st.InvalidConfigs {
		fmt.Printf("✗ %s: %s\n", p.File, strings.Join(p.Errors, "; "))
	}
	sealed := 0
	for _, s := range st.Secrets {
		name := s.App + "/" + s.Secret
		switch {
		case s.Error != "":
			fmt.Printf("✗ %s: %s\n", name, s.Error)
		case !s.Sealed:
			fmt.Printf("✗ %s: never sealed (%s)\n", name, s.File)
		case len(s.MissingKeys) > 0 || len(s.OrphanedKeys) > 0:
			fmt.Printf("~ %s: missing %v, orphaned %v\n", name, s.MissingKeys, s.OrphanedKeys)
		}
		if s.Sealed {
			sealed++
		}
	}
	for _, f := range st.OrphanedFiles {
		fmt.Printf("✗ orphaned sealed file %s\n", f)
	}
	mark := "✓"
	if !st.OK {
		mark = "✗"
	}
	fmt.Printf("%s %d config(s), %d secret(s), %d sealed, %d problem(s)\n",
		mark, st.Configs, len(st.Secrets), sealed, st.Problems)
}

func init() {
	statusCmd.Flags().StringVarP(&statusOutput, "output", "o", "text", "Output format: text or json")
	statusCmd.Flags().StringVarP(&configDir, "config-dir", "c", "",
		"Directory containing app config YAML files (default: auto-detected from repo root)")
	rootCmd.AddCommand(statusCmd)
}
