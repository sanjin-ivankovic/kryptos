package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"source.example.com/example-org/kryptos/internal/config"
	"source.example.com/example-org/kryptos/internal/kubeseal"
	"source.example.com/example-org/kryptos/internal/tui"

	"github.com/spf13/cobra"
)

var (
	configDir           string
	controllerNamespace string
	dryRun              bool
	logLevel            string
	verbose             bool
)

// logger is the process-wide structured logger. It's wired up in
// PersistentPreRunE so every subcommand shares one configured handler.
var logger *slog.Logger

var rootCmd = &cobra.Command{
	Use:   "kryptos",
	Short: "Kryptos — Interactive SealedSecret Generator",
	Long: `Kryptos is an interactive CLI tool for generating Kubernetes SealedSecrets.

It provides a rich TUI for managing secrets across multiple applications,
with support for generating multiple secrets per session without restarting.
`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
		return setupLogger()
	},
	RunE: func(_ *cobra.Command, _ []string) error {
		layout, err := resolveLayout()
		if err != nil {
			return err
		}

		appConfigs, err := loadAllConfigs(layout.ConfigDir)
		if err != nil {
			return err
		}

		if dryRun {
			logger.Info("dry-run mode: secrets will be printed but not sealed or written")
		}

		// Initialize kubeseal (skipped in dry-run)
		var sealer *kubeseal.Sealer
		if !dryRun {
			sealer, err = kubeseal.NewSealer(layout.ControllerNamespace)
			if err != nil {
				return fmt.Errorf("kubeseal not available: %w\nMake sure kubeseal is installed and in PATH", err)
			}
			if connErr := sealer.CheckConnectivity(); connErr != nil {
				logger.Warn("could not reach sealed-secrets controller; proceeding (offline sealing may fail if cert is not cached)",
					"error", connErr)
			}
		}

		return tui.RunWorkflow(appConfigs, sealer, layout, dryRun)
	},
}

// loadAllConfigs reads every config in dir, logging (but not failing on) the
// ones that don't parse — the interactive workflow can still proceed with the
// configs that loaded. `kryptos validate` uses a stricter loader that fails.
func loadAllConfigs(dir string) ([]*config.AppConfig, error) {
	files, err := config.ListConfigs(dir)
	if err != nil {
		return nil, fmt.Errorf("listing configs from %s: %w", dir, err)
	}

	var appConfigs []*config.AppConfig
	for _, f := range files {
		cfg, err := config.LoadConfig(f)
		if err != nil {
			logger.Warn("could not load config; skipping", "file", f, "error", err)
			continue
		}
		appConfigs = append(appConfigs, cfg)
	}

	if len(appConfigs) == 0 {
		return nil, fmt.Errorf("no valid configurations found in %s", dir)
	}
	return appConfigs, nil
}

// setupLogger configures the package logger from the --log-level / --verbose
// flags. Output is a text handler to stderr, leaving stdout for the TUI and
// for any data a subcommand prints. --verbose is a shorthand for debug.
func setupLogger() error {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	} else if logLevel != "" {
		switch strings.ToLower(logLevel) {
		case "debug":
			level = slog.LevelDebug
		case "info":
			level = slog.LevelInfo
		case "warn", "warning":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		default:
			return fmt.Errorf("invalid --log-level %q (want: debug, info, warn, error)", logLevel)
		}
	}
	logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)
	return nil
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "",
		"Log verbosity: debug, info, warn, error (default: info)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"Verbose output (shorthand for --log-level debug)")

	rootCmd.Flags().StringVarP(&configDir, "config-dir", "c", "",
		"Directory containing app config YAML files (default: auto-detected from repo root)")
	rootCmd.Flags().StringVar(&controllerNamespace, "controller-namespace", "kube-system",
		"Namespace where the sealed-secrets controller is running")
	rootCmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"Print what would be generated without sealing or writing files")
}
