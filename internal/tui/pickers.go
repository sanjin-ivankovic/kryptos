package tui

import (
	"fmt"
	"strings"

	huh "charm.land/huh/v2"
	lipgloss "charm.land/lipgloss/v2"

	"source.example.com/example-org/kryptos/internal/config"
	"source.example.com/example-org/kryptos/internal/secrets"
)

// This file holds the huh-based interactive pickers and confirmation prompts.
// They wire user input to the workflow and are intentionally left untested
// (they require a TTY); the logic they feed lives in the testable files.

// nextAction enumerates what the user wants to do after a batch of secrets
// finishes. Declared as a named string type so huh.NewSelect can surface a
// typed result instead of stringly-coded branches.
type nextAction string

const (
	nextSameApp      nextAction = "same"
	nextDifferentApp nextAction = "different"
	nextExit         nextAction = "exit"
)

// promptNextAction asks the user how to proceed after a successful
// batch. The "same app" option short-circuits the app picker for the
// common case of "I forgot a secret in this app".
func promptNextAction(app *config.AppConfig) (nextAction, error) {
	var choice nextAction
	options := []huh.Option[nextAction]{
		huh.NewOption("Same app — more secrets in "+app.DisplayName, nextSameApp),
		huh.NewOption("Different app", nextDifferentApp),
		huh.NewOption("Exit", nextExit),
	}

	err := huh.NewSelect[nextAction]().
		Title("What's next?").
		Description("Application: " + app.DisplayName + " (" + app.Namespace + ")").
		Options(options...).
		Value(&choice).
		Run()
	if err != nil {
		return "", err
	}
	return choice, nil
}

// selectApp presents a single-select list of all configured applications.
func selectApp(appConfigs []*config.AppConfig) (*config.AppConfig, error) {
	var selected string
	options := make([]huh.Option[string], len(appConfigs))
	for i, app := range appConfigs {
		label := app.DisplayName + "  (" + app.Namespace + ")"
		options[i] = huh.NewOption(label, app.AppName)
	}

	err := huh.NewSelect[string]().
		Title("Kryptos — Sealed Secret Generator").
		Description("Select an application to generate secrets for").
		Options(options...).
		Value(&selected).
		Run()
	if err != nil {
		return nil, err
	}

	for _, app := range appConfigs {
		if app.AppName == selected {
			return app, nil
		}
	}
	return nil, fmt.Errorf("application %q not found", selected)
}

// selectSecrets presents a multi-select list of secrets for the chosen app.
// If only one secret is configured, it is returned directly without a prompt.
func selectSecrets(app *config.AppConfig) ([]config.Secret, error) {
	if len(app.Secrets) == 0 {
		return nil, fmt.Errorf("no secrets configured for %s", app.DisplayName)
	}
	if len(app.Secrets) == 1 {
		return app.Secrets, nil
	}

	// Option labels use the secret's displayName ONLY (short, single
	// line, never wraps). The description is shown in the per-secret
	// form that follows so the user still gets to read it before
	// entering values. Earlier, we concatenated "displayName —
	// description" into one label which hard-wrapped mid-word at the
	// terminal edge.
	var selectedNames []string
	options := make([]huh.Option[string], len(app.Secrets))
	for i, s := range app.Secrets {
		options[i] = huh.NewOption(s.DisplayName, s.Name)
	}

	// Compute the rendered height each option will occupy. Long labels
	// wrap to multiple rows, and the user wants every option visible
	// without scrolling. huh's MultiSelect computes its viewport
	// height as:
	//
	//   max(minHeight, height) - yoffset
	//
	// where yoffset is the title + description rows. To make the
	// viewport land at exactly the total rendered option height,
	// pass `Height(total_option_rows + yoffset)`. lipgloss.Height
	// gives us the rendered row count for any wrapped string at the
	// current terminal width.
	titleRows := lipgloss.Height("Select Secrets to Generate")
	descRows := lipgloss.Height("Application: " + app.DisplayName + " (" + app.Namespace + ")")
	optionRows := 0
	for _, opt := range options {
		optionRows += lipgloss.Height(opt.Key)
	}
	height := optionRows + titleRows + descRows

	err := huh.NewMultiSelect[string]().
		Title("Select Secrets to Generate").
		Description("Application: " + app.DisplayName + " (" + app.Namespace + ")").
		Options(options...).
		Height(height).
		Validate(func(v []string) error {
			if len(v) == 0 {
				return fmt.Errorf("select at least one secret (Space to toggle, Enter to confirm)")
			}
			return nil
		}).
		Value(&selectedNames).
		Run()
	if err != nil {
		return nil, err
	}

	nameSet := make(map[string]bool, len(selectedNames))
	for _, n := range selectedNames {
		nameSet[n] = true
	}
	var result []config.Secret
	for _, s := range app.Secrets {
		if nameSet[s.Name] {
			result = append(result, s)
		}
	}
	return result, nil
}

// secretAction is what the user wants to do with a secret whose sealed file
// already exists: merge in one field, or re-seal the whole thing.
type secretAction string

const (
	actionAddField secretAction = "add"
	actionReseal   secretAction = "reseal"
	actionSkip     secretAction = "skip"
)

// promptExistingSecretAction is shown when a selected secret is already sealed.
// Re-sealing regenerates every generator field, so the non-destructive
// "add a field" path is offered first and is the default.
func promptExistingSecretAction(secret *config.Secret, w secrets.ResealWarning) (secretAction, error) {
	desc := w.Filename + " already exists."
	if len(w.Regenerated) > 0 {
		desc += "\nRe-sealing gives these keys NEW random values: " +
			strings.Join(w.Regenerated, ", ")
	}
	if len(w.Preserved) > 0 {
		desc += "\nPreserved: " + strings.Join(w.Preserved, ", ")
	}

	title := secret.DisplayName
	if title == "" {
		title = secret.Name
	}

	var choice secretAction
	err := huh.NewSelect[secretAction]().
		Title(title).
		Description(desc).
		Options(
			huh.NewOption("Add a single field (keeps every existing value)", actionAddField),
			huh.NewOption("Re-seal everything (regenerates the keys listed above)", actionReseal),
			huh.NewOption("Skip this secret", actionSkip),
		).
		Value(&choice).
		Run()
	if err != nil {
		return "", err
	}
	return choice, nil
}

// selectAddableField asks which declared field to merge in, offering the fields
// that are not yet present in the sealed file. Derived fields are excluded:
// they are computed from siblings at seal time, so adding one alone is
// meaningless (AddField rejects them too).
func selectAddableField(secret *config.Secret, sealedKeys []string) (string, error) {
	inFile := make(map[string]bool, len(sealedKeys))
	for _, k := range sealedKeys {
		inFile[k] = true
	}

	var options []huh.Option[string]
	for _, f := range secret.Fields {
		if f.Derive != "" || inFile[f.Name] {
			continue
		}
		label := f.Name
		if f.Prompt != "" {
			label = f.Prompt + "  (" + f.Name + ")"
		}
		options = append(options, huh.NewOption(label, f.Name))
	}
	if len(options) == 0 {
		return "", fmt.Errorf("every declared field of %q is already sealed; "+
			"add a new field to the config first", secret.Name)
	}

	var choice string
	err := huh.NewSelect[string]().
		Title("Which field should be added?").
		Description("Only fields not yet in the sealed file are listed.").
		Options(options...).
		Value(&choice).
		Run()
	if err != nil {
		return "", err
	}
	return choice, nil
}

// promptFieldValue collects the value for a single field, seeding a generator
// field with a freshly generated value the user can accept or replace.
func promptFieldValue(secret *config.Secret, fieldName string) (string, error) {
	var field config.SecretField
	for _, f := range secret.Fields {
		if f.Name == fieldName {
			field = f
			break
		}
	}

	value := field.Default
	if field.Generator != "" {
		gen, err := secrets.GenerateFieldValue(field)
		if err != nil {
			return "", fmt.Errorf("pre-generating %s: %w", fieldName, err)
		}
		value = gen
	}

	prompt := field.Prompt
	if prompt == "" {
		prompt = field.Name
	}
	help := field.Help
	if help == "" && field.Generator != "" {
		help = "Auto-generated — edit to override, or clear and type a magic keyword: secure · strong · apikey · passphrase"
	}

	if field.Multiline {
		f := huh.NewText().Title(prompt).Value(&value)
		if help != "" {
			f = f.Description(help)
		}
		if err := huh.NewForm(huh.NewGroup(f)).Run(); err != nil {
			return "", err
		}
	} else {
		f := huh.NewInput().Title(prompt).Value(&value)
		if help != "" {
			f = f.Description(help)
		}
		if fieldIsMasked(field) {
			f = f.EchoMode(huh.EchoModePassword)
		}
		if field.Required {
			f = f.Validate(func(v string) error {
				if strings.TrimSpace(v) == "" {
					return fmt.Errorf("%s is required", prompt)
				}
				return nil
			})
		}
		if err := huh.NewForm(huh.NewGroup(f)).Run(); err != nil {
			return "", err
		}
	}

	return secrets.ExpandMagicKeyword(value, field)
}

// confirmOverwrite asks before clobbering an existing sealed-secret file.
func confirmOverwrite(filename string) bool {
	var overwrite bool
	_ = huh.NewConfirm().
		Title(fmt.Sprintf("'%s' already exists. Overwrite?", filename)).
		Affirmative("Yes, overwrite").
		Negative("No, skip").
		Value(&overwrite).
		Run()
	return overwrite
}

// confirmContinueOnError asks the user whether to continue after a generation failure.
func confirmContinueOnError(secretName string, err error) bool {
	var continueAfterError bool
	_ = huh.NewConfirm().
		Title(fmt.Sprintf("Failed to generate '%s'", secretName)).
		Description(err.Error()).
		Affirmative("Continue with remaining secrets").
		Negative("Stop").
		Value(&continueAfterError).
		Run()
	return continueAfterError
}
