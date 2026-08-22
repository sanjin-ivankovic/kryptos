package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Build metadata, injected at release time via -ldflags (see .goreleaser.yaml).
// Defaults make a `go build` / `go run` dev binary self-describe as such.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var versionCmd = &cobra.Command{
	Use:           "version",
	Short:         "Print the kryptos version",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		fmt.Printf("kryptos %s (commit %s, built %s, %s/%s)\n",
			version, commit, date, runtime.GOOS, runtime.GOARCH)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
