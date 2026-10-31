package secrets

import (
	"fmt"
	"os"
	"sort"

	"source.example.com/example-org/kryptos/internal/config"
	"source.example.com/example-org/kryptos/internal/generator"
	"source.example.com/example-org/kryptos/internal/kubeseal"
)

// Result holds the outcome of generating a single sealed secret.
type Result struct {
	SecretName  string
	DisplayName string
	OutputPath  string
	Err         error
}

// ValueResolver supplies the values for a secret's non-derived fields. The
// interactive front-end implements this with a huh form (seeded with
// pre-generated generator values); the non-interactive front-end resolves from
// --values/env/flags plus generator auto-fill. Implementations must return a
// map keyed by field name covering every non-derived field that should appear
// in the secret (derived fields are computed afterwards by ApplyDerivedFields).
type ValueResolver func(secret *config.Secret) (map[string]string, error)

// Hooks lets a front-end observe/steer the pipeline without the core importing
// any UI. All are optional; nil hooks use safe defaults (overwrite allowed,
// dry-run printed as key: <masked>).
type Hooks struct {
	// ConfirmOverwrite is asked before clobbering an existing output file.
	// Returning false skips the write. Nil = always overwrite.
	//
	// When the front-end also sets ConfirmReseal, that hook is consulted first
	// and this one is only reached if the reseal was approved.
	ConfirmOverwrite func(filename string) bool
	// ConfirmReseal is asked before re-sealing a secret whose output file
	// already exists, and is told exactly which keys the reseal would
	// regenerate. Returning false aborts the write.
	//
	// It is separate from ConfirmOverwrite because the two answer different
	// questions: ConfirmOverwrite asks "replace this file?", while this asks
	// "accept that these specific keys get brand-new random values?". Only the
	// latter can convey the data loss, since a rotated generator field's old
	// value is unrecoverable. Nil = no reseal confirmation.
	ConfirmReseal func(ResealWarning) bool
	// EmitDryRun renders a dry-run preview. Nil = no output.
	EmitDryRun func(app *config.AppConfig, secret *config.Secret, data map[string]string)
}

// ResealWarning describes what re-sealing an existing secret would do to the
// keys already in its sealed file, so a front-end can show the damage before it
// happens.
type ResealWarning struct {
	App    string
	Secret string
	// Filename is the sealed file's base name.
	Filename string
	// Regenerated lists the already-sealed keys that carry a generator and
	// would therefore receive NEW random values, discarding what is in the
	// file. These are the keys that break live systems.
	Regenerated []string
	// Preserved lists the already-sealed keys that would keep an equivalent
	// value (supplied explicitly, static, or derived from such a value).
	Preserved []string
}

// ResealImpact computes, for a secret whose sealed file already exists, which
// of its currently-sealed keys a re-seal would regenerate versus preserve.
//
// A non-derived field with a generator gets a fresh random value on every
// resolve, so re-sealing rotates it. Derived fields recompute from their
// sources and so are only listed as regenerated when a source rotates; they are
// otherwise reported as preserved.
func ResealImpact(app *config.AppConfig, secret *config.Secret, sealedPath string) (ResealWarning, error) {
	warning := ResealWarning{
		App:      app.AppName,
		Secret:   secret.Name,
		Filename: baseName(sealedPath),
	}

	sealed, err := SealedKeys(sealedPath)
	if err != nil {
		return warning, err
	}
	inFile := toSet(sealed)

	// Generator fields rotate; every other declared field keeps its value.
	rotating := make(map[string]bool)
	for _, f := range secret.Fields {
		if f.Derive == "" && f.Generator != "" {
			rotating[f.Name] = true
		}
	}
	// A derived field follows its source: if the source rotates, so does it.
	for _, f := range secret.Fields {
		if f.Derive != "" && f.DeriveFrom != "" && rotating[f.DeriveFrom] {
			rotating[f.Name] = true
		}
	}

	for _, key := range sealed {
		if !inFile[key] {
			continue
		}
		if rotating[key] {
			warning.Regenerated = append(warning.Regenerated, key)
		} else {
			warning.Preserved = append(warning.Preserved, key)
		}
	}
	sort.Strings(warning.Regenerated)
	sort.Strings(warning.Preserved)
	return warning, nil
}

// Pipeline runs the shared seal flow for one secret:
//
//	resolve non-derived values → ApplyDerivedFields → merge static stringData →
//	(dry-run preview | GenerateRawSecret → Seal → write file)
//
// It is UI-agnostic: the front-end injects how values are obtained (Resolve)
// and how interactive decisions are made (Hooks).
type Pipeline struct {
	Layout *config.Layout
	Sealer *kubeseal.Sealer // may be nil in dry-run
	DryRun bool
	Hooks  Hooks
}

// Process runs the pipeline for a single secret and returns its Result. Errors
// are returned inside Result.Err (not as a separate error) so a batch can
// collect per-secret outcomes.
func (p *Pipeline) Process(app *config.AppConfig, secret *config.Secret, resolve ValueResolver) Result {
	result := Result{SecretName: secret.Name, DisplayName: secret.DisplayName}

	// Ask about re-sealing BEFORE resolving. Resolution is what mints new
	// generator values, and in the TUI it is also what prompts the user for
	// input — so a confirmation asked afterwards would come too late to be a
	// warning and would waste the user's typing. Dry-run seals nothing, so it
	// skips the prompt.
	if !p.DryRun && p.Hooks.ConfirmReseal != nil {
		if path, err := p.Layout.OutputPath(app.AppName, secret); err == nil {
			if _, statErr := os.Stat(path); statErr == nil {
				warning, wErr := ResealImpact(app, secret, path)
				if wErr != nil {
					result.Err = wErr
					return result
				}
				if !p.Hooks.ConfirmReseal(warning) {
					result.Err = fmt.Errorf("skipped (re-seal not confirmed)")
					return result
				}
			}
		}
	}

	data, err := resolve(secret)
	if err != nil {
		result.Err = err
		return result
	}

	// Compute derived field values from their sibling sources. In dry-run we
	// don't touch the cluster, so cluster_secret derives emit a placeholder.
	if err := ApplyDerivedFields(secret, data, p.DryRun); err != nil {
		result.Err = fmt.Errorf("deriving fields: %w", err)
		return result
	}

	// Merge static string data from config (resolved values take precedence).
	for k, v := range secret.StringData {
		if _, exists := data[k]; !exists {
			data[k] = v
		}
	}

	if p.DryRun {
		if p.Hooks.EmitDryRun != nil {
			p.Hooks.EmitDryRun(app, secret, data)
		}
		result.OutputPath = "(dry-run)"
		return result
	}

	rawSecret, err := generator.GenerateRawSecret(app, *secret, data)
	if err != nil {
		result.Err = fmt.Errorf("generating secret: %w", err)
		return result
	}

	sealedSecret, err := p.Sealer.Seal(rawSecret, app.Namespace, secret.Name)
	if err != nil {
		result.Err = fmt.Errorf("sealing: %w", err)
		return result
	}

	outputPath, err := p.Layout.OutputPath(app.AppName, secret)
	if err != nil {
		result.Err = fmt.Errorf("resolving output path: %w", err)
		return result
	}

	if _, err := os.Stat(outputPath); err == nil && p.Hooks.ConfirmOverwrite != nil {
		if !p.Hooks.ConfirmOverwrite(baseName(outputPath)) {
			result.Err = fmt.Errorf("skipped (file exists, not overwritten)")
			return result
		}
	}

	if err := os.WriteFile(outputPath, sealedSecret, 0o600); err != nil {
		result.Err = fmt.Errorf("writing file: %w", err)
		return result
	}

	result.OutputPath = outputPath
	return result
}

// PregenerateValues returns auto-generated values for every non-derived field
// that has a generator directive. Used to seed the interactive form's defaults
// and to auto-fill generator fields in the non-interactive resolver.
func PregenerateValues(secret *config.Secret) (map[string]string, error) {
	out := make(map[string]string)
	for _, field := range secret.Fields {
		if field.Derive != "" {
			continue
		}
		val, err := GenerateFieldValue(field)
		if err != nil {
			return nil, fmt.Errorf("pre-generating %s: %w", field.Name, err)
		}
		if val != "" {
			out[field.Name] = val
		}
	}
	return out, nil
}

// baseName returns the final path element without importing path/filepath at
// every call site.
func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[i+1:]
		}
	}
	return p
}
