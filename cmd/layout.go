package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"source.example.com/example-org/kryptos/internal/config"
	"source.example.com/example-org/kryptos/internal/kubeseal"
)

// resolveLayout loads the kryptos.toml-driven Layout and applies CLI flag
// overrides. A --config-dir flag overrides the layout's ConfigDir; a
// --controller-namespace other than the built-in default overrides the
// layout's ControllerNamespace. Every subcommand that touches paths or the
// controller goes through here so flag/​toml/​default precedence is uniform.
func resolveLayout() (*config.Layout, error) {
	layout, err := config.LoadLayout()
	if err != nil {
		return nil, err
	}
	if configDir != "" {
		layout.ConfigDir = configDir
	}
	// controllerNamespace defaults to "kube-system" via the flag definition;
	// only override the layout when the user passed something different, so a
	// kryptos.toml controller_namespace isn't silently clobbered by the flag
	// default.
	if controllerNamespace != "" && controllerNamespace != "kube-system" {
		layout.ControllerNamespace = controllerNamespace
	}
	if certFile != "" {
		abs, err := filepath.Abs(certFile)
		if err != nil {
			return nil, err
		}
		layout.CertPath = abs
	}
	return layout, nil
}

// newSealer builds the kubeseal wrapper for layout. With a certificate
// (--cert or cert_path) it seals offline, so the file must exist.
func newSealer(layout *config.Layout) (*kubeseal.Sealer, error) {
	if layout.CertPath != "" {
		if _, err := os.Stat(layout.CertPath); err != nil {
			return nil, fmt.Errorf("controller certificate %s: %w (run kryptos cert fetch)", layout.CertPath, err)
		}
	}
	sealer, err := kubeseal.NewSealer(layout.ControllerNamespace)
	if err != nil {
		return nil, err
	}
	sealer.Cert = layout.CertPath
	return sealer, nil
}
