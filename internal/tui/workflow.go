// Package tui provides the interactive terminal workflow for Kryptos.
//
// The package is split by concern:
//
//	workflow.go — orchestration: the RunWorkflow loop wiring the secrets pipeline
//	pickers.go  — huh select/confirm prompts (app, secrets, next action)
//	form.go     — the dynamic per-secret input form (the interactive ValueResolver)
//	output.go   — summary + dry-run rendering
//
// The value-generation and derive logic lives in internal/secrets (UI-agnostic,
// shared with the non-interactive seal/rotate commands); this package only
// supplies the huh-based ValueResolver and prompts.
package tui

import (
	"fmt"
	"os"

	huh "charm.land/huh/v2"
	lipgloss "charm.land/lipgloss/v2"

	"source.example.com/example-org/kryptos/internal/config"
	"source.example.com/example-org/kryptos/internal/kubeseal"
	"source.example.com/example-org/kryptos/internal/secrets"
)

// Result aliases the shared pipeline result so existing tui callers and output
// helpers keep working.
type Result = secrets.Result

// RunWorkflow runs the interactive secret generation workflow.
// It loops, offering to generate more secrets — either from the same
// app (skipping the app-picker) or from a different app — until the
// user exits.
func RunWorkflow(appConfigs []*config.AppConfig, sealer *kubeseal.Sealer, layout *config.Layout, dryRun bool) error {
	pipeline := &secrets.Pipeline{
		Layout: layout,
		Sealer: sealer,
		DryRun: dryRun,
		Hooks: secrets.Hooks{
			// No ConfirmReseal here: processSecret runs the richer
			// add-vs-reseal prompt before resolving, so reaching Process
			// already means the user accepted the rotation. ConfirmOverwrite
			// remains as the final "replace this file?" check.
			ConfirmOverwrite: confirmOverwrite,
			EmitDryRun:       printDryRun,
		},
	}

	var currentApp *config.AppConfig

	for {
		// Step 1: Select an application, unless we already have one
		// from the previous iteration's "same app" choice.
		if currentApp == nil {
			app, err := selectApp(appConfigs)
			if err != nil {
				if err == huh.ErrUserAborted {
					printExit()
					return nil
				}
				return fmt.Errorf("app selection: %w", err)
			}
			currentApp = app
		}

		// Step 2: Multi-select secrets to generate
		selected, err := selectSecrets(currentApp)
		if err != nil {
			if err == huh.ErrUserAborted {
				currentApp = nil // back to app picker
				continue
			}
			return fmt.Errorf("secret selection: %w", err)
		}
		if len(selected) == 0 {
			currentApp = nil
			continue
		}

		// Step 3: For each selected secret, fill in the form and generate.
		// A secret that is already sealed goes through the add-vs-reseal
		// prompt first, so the destructive path is never the default.
		var results []Result
		for i := range selected {
			secret := selected[i]
			result := processSecret(pipeline, currentApp, &secret, dryRun)
			results = append(results, result)
			if result.Err != nil && !confirmContinueOnError(result.DisplayName, result.Err) {
				break
			}
		}

		// Step 4: Print summary
		printSummary(results)

		// Step 5: Three-way prompt — same app, different app, or exit.
		next, err := promptNextAction(currentApp)
		if err != nil {
			if err == huh.ErrUserAborted {
				printExit()
				return nil
			}
			return fmt.Errorf("next-action prompt: %w", err)
		}
		switch next {
		case nextSameApp:
			// Keep currentApp; loop straight back to selectSecrets.
		case nextDifferentApp:
			currentApp = nil
		case nextExit:
			printExit()
			return nil
		}
	}
}

// processSecret runs one secret through the pipeline, routing to the
// non-destructive add-a-field path when its sealed file already exists.
//
// Re-sealing an existing secret hands every generator field a new random value,
// and sealed values cannot be read back — so when the file is there, the user
// is shown exactly which keys a re-seal would rotate and gets to merge in a
// single field instead. In dry-run nothing is written, so the normal preview
// path runs unchanged.
func processSecret(p *secrets.Pipeline, app *config.AppConfig, secret *config.Secret, dryRun bool) Result {
	if dryRun {
		return p.Process(app, secret, interactiveResolver)
	}

	path, err := p.Layout.OutputPath(app.AppName, secret)
	if err != nil {
		return Result{SecretName: secret.Name, DisplayName: secret.DisplayName, Err: err}
	}
	if _, statErr := os.Stat(path); statErr != nil {
		// Nothing sealed yet: the ordinary full-seal path is safe.
		return p.Process(app, secret, interactiveResolver)
	}

	warning, err := secrets.ResealImpact(app, secret, path)
	if err != nil {
		return Result{SecretName: secret.Name, DisplayName: secret.DisplayName, Err: err}
	}

	action, err := promptExistingSecretAction(secret, warning)
	if err != nil {
		return Result{SecretName: secret.Name, DisplayName: secret.DisplayName,
			Err: fmt.Errorf("aborted by user")}
	}

	switch action {
	case actionSkip:
		return Result{SecretName: secret.Name, DisplayName: secret.DisplayName,
			Err: fmt.Errorf("skipped (already sealed)")}

	case actionAddField:
		sealedKeys, err := secrets.SealedKeys(path)
		if err != nil {
			return Result{SecretName: secret.Name, DisplayName: secret.DisplayName, Err: err}
		}
		fieldName, err := selectAddableField(secret, sealedKeys)
		if err != nil {
			return Result{SecretName: secret.Name, DisplayName: secret.DisplayName, Err: err}
		}
		value, err := promptFieldValue(secret, fieldName)
		if err != nil {
			return Result{SecretName: secret.Name, DisplayName: secret.DisplayName, Err: err}
		}
		return p.AddField(secrets.AddFieldRequest{
			App: app, Secret: secret, Field: fieldName, Value: value,
		})

	default: // actionReseal — the user saw the rotation list and accepted it.
		return p.Process(app, secret, interactiveResolver)
	}
}

// interactiveResolver is the ValueResolver for the TUI: it pre-generates
// generator defaults, runs the huh form, and returns the entered/expanded
// values for the secret's non-derived fields. The pipeline takes it from here
// (derive → generate → seal → write).
func interactiveResolver(secret *config.Secret) (map[string]string, error) {
	// Pre-generate values from generator directives so they appear as defaults
	// in the form. Derived fields are skipped — they're computed by the
	// pipeline after the form returns, from a sibling field's value.
	pregenValues, err := secrets.PregenerateValues(secret)
	if err != nil {
		return nil, err
	}

	data, err := runSecretForm(secret, pregenValues)
	if err != nil {
		if err == huh.ErrUserAborted {
			return nil, fmt.Errorf("aborted by user")
		}
		return nil, fmt.Errorf("form input: %w", err)
	}
	return data, nil
}

// printExit prints a farewell message.
func printExit() {
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	fmt.Println(style.Render("\nGoodbye!"))
}
