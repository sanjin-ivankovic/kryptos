package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"source.example.com/example-org/kryptos/internal/kubeseal"

	"github.com/spf13/cobra"
)

var certOut string

var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "Manage the controller certificate used for offline sealing",
}

var certFetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Save the controller's current public certificate for offline sealing",
	Long: `Fetch saves the sealed-secrets controller's current public certificate to
cert_path from kryptos.toml, or to --out. With a certificate set (cert_path or
--cert), seal, add, rotate and the TUI encrypt against it without contacting
the controller. The certificate is public; sealing needs nothing secret.

The controller renews its sealing key every 30 days by default and keeps the
old ones, so a saved certificate keeps working. Fetch again, then run
kryptos reseal, to move sealed files to the newest key.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		layout, err := resolveLayout()
		if err != nil {
			return err
		}
		out := certOut
		if out == "" {
			out = layout.CertPath
		}
		if out == "" {
			return fmt.Errorf("no destination: set cert_path in kryptos.toml or pass --out")
		}
		sealer, err := kubeseal.NewSealer(layout.ControllerNamespace)
		if err != nil {
			return fmt.Errorf("kubeseal not available: %w", err)
		}
		pem, err := sealer.FetchCert()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(out, pem, 0o600); err != nil {
			return err
		}
		fmt.Printf("✓ controller certificate → %s\n", out)
		return nil
	},
}

func init() {
	certFetchCmd.Flags().StringVar(&certOut, "out", "", "Write the certificate here (default: cert_path from kryptos.toml)")
	certCmd.AddCommand(certFetchCmd)
	rootCmd.AddCommand(certCmd)
}
