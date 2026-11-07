package secrets

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"source.example.com/example-org/kryptos/internal/config"
)

// AddFieldRequest describes a single-field addition to an already-sealed
// secret. It is deliberately narrow: adding a field is the safe alternative to
// re-sealing, so it takes exactly one field and one value.
type AddFieldRequest struct {
	App    *config.AppConfig
	Secret *config.Secret
	// Field is the name of the field to add. It must be declared in
	// Secret.Fields — adding an undeclared key would create a data key that no
	// config knows about, which `audit` would then report as orphaned.
	Field string
	// Value is the already-resolved value for Field. Resolution (flag, file,
	// env, generator, default) belongs to the front-end, exactly as with
	// ValueResolver, so this package stays UI- and CLI-agnostic.
	Value string
	// Overwrite permits re-sealing a field that is already present in the
	// sealed file. This rotates that key, so it is off by default.
	Overwrite bool
}

// AddField encrypts one value and merges it into an existing SealedSecret file,
// leaving every other key's ciphertext byte-identical.
//
// This exists because Process re-resolves every field: any field carrying a
// `generator` directive gets a NEW random value on each run, so re-sealing a
// multi-field secret just to add one field silently rotates all the others.
// Sealed values cannot be read back (see SealedKeys — we only ever see the key
// set, never the plaintext), so a rotated key is unrecoverable from the file
// alone.
//
// The guards below are the point of the function; each one blocks a way of
// destroying or orphaning existing data.
func (p *Pipeline) AddField(req AddFieldRequest) Result {
	result := Result{SecretName: req.Secret.Name, DisplayName: req.Secret.DisplayName}

	field, err := findAddableField(req.Secret, req.Field)
	if err != nil {
		result.Err = err
		return result
	}

	// Resolve the output path exactly as Process does, so both commands agree
	// on which file backs a given secret.
	outputPath, err := p.Layout.OutputPath(req.App.AppName, req.Secret)
	if err != nil {
		result.Err = fmt.Errorf("resolving output path: %w", err)
		return result
	}

	// The sealed file must already exist: merging is defined only against an
	// existing SealedSecret, and creating one here would seal a secret holding
	// a single field while silently omitting every other declared field.
	if _, statErr := os.Stat(outputPath); statErr != nil {
		if os.IsNotExist(statErr) {
			result.Err = fmt.Errorf(
				"no sealed secret at %s: run `kryptos seal %s %s` to create it first "+
					"(add only merges a field into an existing sealed secret)",
				outputPath, req.App.AppName, req.Secret.Name)
			return result
		}
		result.Err = fmt.Errorf("checking %s: %w", outputPath, statErr)
		return result
	}

	// Adding a key that is already sealed would re-encrypt it — i.e. rotate it,
	// which is the exact failure mode this command exists to avoid.
	existing, err := SealedKeys(outputPath)
	if err != nil {
		result.Err = err
		return result
	}
	if containsKey(existing, req.Field) && !req.Overwrite {
		result.Err = fmt.Errorf(
			"field %q is already sealed in %s; adding it again would replace (rotate) "+
				"its current value. Pass --force only if you intend to change it",
			req.Field, baseName(outputPath))
		return result
	}

	if p.DryRun {
		if p.Hooks.EmitDryRun != nil {
			p.Hooks.EmitDryRun(req.App, req.Secret, map[string]string{field.Name: req.Value})
		}
		result.OutputPath = "(dry-run)"
		return result
	}

	if err := p.Sealer.SealRawInto(
		[]byte(req.Value), req.App.Namespace, req.Secret.Name, req.Field, outputPath,
	); err != nil {
		result.Err = fmt.Errorf("sealing field %q: %w", req.Field, err)
		return result
	}

	result.OutputPath = outputPath
	return result
}

// findAddableField looks up name in the secret's declared fields and rejects
// the kinds of field that cannot meaningfully be added on their own.
func findAddableField(secret *config.Secret, name string) (config.SecretField, error) {
	if name == "" {
		return config.SecretField{}, fmt.Errorf("field name is required")
	}

	for _, f := range secret.Fields {
		if f.Name != name {
			continue
		}
		// A derived field is computed from its siblings at seal time; sealing
		// one in isolation would bake in a value that no longer tracks the
		// fields it is derived from. Re-seal (or rotate) the whole secret
		// instead, which recomputes derives as a set.
		if f.Derive != "" {
			return config.SecretField{}, fmt.Errorf(
				"field %q is derived (derive: %s): it is computed from its sibling fields at "+
					"seal time, so adding it on its own is meaningless. Re-seal the secret to "+
					"recompute it", name, f.Derive)
		}
		return f, nil
	}

	return config.SecretField{}, fmt.Errorf(
		"secret %q has no field named %q; declare it in the config first (declared: %s)",
		secret.Name, name, strings.Join(declaredFieldNames(secret), ", "))
}

// declaredFieldNames lists the secret's non-derived field names, sorted, for
// error messages that point at what the user could have meant.
func declaredFieldNames(secret *config.Secret) []string {
	var names []string
	for _, f := range secret.Fields {
		if f.Derive == "" {
			names = append(names, f.Name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return []string{"none"}
	}
	return names
}

func containsKey(keys []string, want string) bool {
	for _, k := range keys {
		if k == want {
			return true
		}
	}
	return false
}
