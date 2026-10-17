package cmd

import (
	"source.example.com/example-org/kryptos/internal/config"
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
	return layout, nil
}
