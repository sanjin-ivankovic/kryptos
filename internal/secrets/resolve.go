package secrets

import (
	"fmt"
	"sort"
	"strings"

	"source.example.com/example-org/kryptos/internal/config"
)

// ValueSource supplies caller-provided values for a secret's non-derived
// fields in the non-interactive path. Lookup returns the value and whether it
// was present. Implementations: a --values YAML map, environment variables,
// repeated --set flags, or a composite that tries each in order.
type ValueSource interface {
	Lookup(secretName, fieldName string) (string, bool)
}

// NonInteractiveResolver builds a ValueResolver that fills each non-derived
// field, in precedence order:
//
//  1. an explicit value from src (--values / --set / env)
//  2. the field's generator (secure/strong/apikey/passphrase), auto-generated
//  3. the field's static default
//
// A required field left with no value after all three is a hard error (the
// whole point of non-interactive sealing: fail loudly rather than seal a blank).
// The produced map matches what the interactive path yields for the same
// inputs, so the sealed output is identical.
func NonInteractiveResolver(src ValueSource) ValueResolver {
	return func(secret *config.Secret) (map[string]string, error) {
		out := make(map[string]string)
		var missing []string

		for _, field := range secret.Fields {
			if field.Derive != "" {
				continue // derived fields are computed by the pipeline
			}

			// 1. Explicit value (expand a magic keyword if the caller passed one).
			if v, ok := src.Lookup(secret.Name, field.Name); ok {
				expanded, err := ExpandMagicKeyword(v, field)
				if err != nil {
					return nil, fmt.Errorf("field %q: %w", field.Name, err)
				}
				out[field.Name] = expanded
				continue
			}

			// 2. Generator auto-fill.
			if field.Generator != "" {
				gen, err := GenerateFieldValue(field)
				if err != nil {
					return nil, fmt.Errorf("field %q: %w", field.Name, err)
				}
				out[field.Name] = gen
				continue
			}

			// 3. Static default.
			if field.Default != "" {
				expanded, err := ExpandMagicKeyword(field.Default, field)
				if err != nil {
					return nil, fmt.Errorf("field %q: %w", field.Name, err)
				}
				out[field.Name] = expanded
				continue
			}

			// Nothing supplied. Required → hard error; optional → empty value
			// (the interactive form would have accepted an empty entry).
			if field.Required {
				// A required field can still be satisfied by static stringData
				// at generate time; only flag it if it isn't.
				if _, ok := secret.StringData[field.Name]; !ok {
					missing = append(missing, field.Name)
				}
				continue
			}
			out[field.Name] = ""
		}

		if len(missing) > 0 {
			sort.Strings(missing)
			return nil, fmt.Errorf("secret %q: no value, generator, or default for required field(s): %s",
				secret.Name, strings.Join(missing, ", "))
		}
		return out, nil
	}
}

// RotateResolver builds a ValueResolver for `kryptos rotate`. It regenerates
// the targeted generator field(s) with fresh values and re-runs derives (via
// the pipeline) so dependent values recompute — e.g. rotating a password also
// recomputes its htpasswd sibling, for free, in one pass.
//
// fields selects which generator fields to rotate; empty means ALL of the
// secret's generator fields. A non-targeted, non-derived field is taken from
// src (then its default); a required one with neither is a hard error, because
// sealed values are encrypted at rest and cannot be carried over — the caller
// must supply anything that isn't being regenerated.
//
// Targeting a field that has no generator is an error: there's nothing to
// rotate (use seal to set an explicit value).
func RotateResolver(src ValueSource, fields []string) ValueResolver {
	target := make(map[string]bool, len(fields))
	for _, f := range fields {
		target[f] = true
	}

	return func(secret *config.Secret) (map[string]string, error) {
		// Validate the requested fields exist and are generators.
		if len(target) > 0 {
			byName := make(map[string]config.SecretField, len(secret.Fields))
			for _, f := range secret.Fields {
				byName[f.Name] = f
			}
			for name := range target {
				f, ok := byName[name]
				if !ok {
					return nil, fmt.Errorf("secret %q has no field %q to rotate", secret.Name, name)
				}
				if f.Generator == "" {
					return nil, fmt.Errorf("field %q has no generator; nothing to rotate (use `seal --set` to set a value)", name)
				}
			}
		}

		out := make(map[string]string)
		var missing []string

		for _, field := range secret.Fields {
			if field.Derive != "" {
				continue
			}

			rotateThis := field.Generator != "" && (len(target) == 0 || target[field.Name])
			if rotateThis {
				gen, err := GenerateFieldValue(field)
				if err != nil {
					return nil, fmt.Errorf("field %q: %w", field.Name, err)
				}
				out[field.Name] = gen
				continue
			}

			// Not being rotated: take a supplied value, then a default.
			if v, ok := src.Lookup(secret.Name, field.Name); ok {
				expanded, err := ExpandMagicKeyword(v, field)
				if err != nil {
					return nil, fmt.Errorf("field %q: %w", field.Name, err)
				}
				out[field.Name] = expanded
				continue
			}
			if field.Default != "" {
				out[field.Name] = field.Default
				continue
			}
			if field.Required {
				if _, ok := secret.StringData[field.Name]; !ok {
					missing = append(missing, field.Name)
				}
				continue
			}
			out[field.Name] = ""
		}

		if len(missing) > 0 {
			sort.Strings(missing)
			return nil, fmt.Errorf("secret %q: rotation needs values for non-rotated required field(s) "+
				"(sealed values can't be read back): %s", secret.Name, strings.Join(missing, ", "))
		}
		return out, nil
	}
}

// MapSource is a ValueSource backed by an in-memory map keyed "secret.field"
// (preferred) with a bare "field" fallback so callers can target a field across
// any secret. Built from --values YAML and --set flags.
type MapSource struct {
	// keyed by "secret.field"
	byQualified map[string]string
	// keyed by "field" (applies to any secret unless a qualified key wins)
	byField map[string]string
}

// NewMapSource builds a MapSource. qualified entries ("secret.field") take
// precedence over bare ("field") entries.
func NewMapSource(qualified, bare map[string]string) *MapSource {
	return &MapSource{byQualified: qualified, byField: bare}
}

// Lookup implements ValueSource.
func (m *MapSource) Lookup(secretName, fieldName string) (string, bool) {
	if m.byQualified != nil {
		if v, ok := m.byQualified[secretName+"."+fieldName]; ok {
			return v, true
		}
	}
	if m.byField != nil {
		if v, ok := m.byField[fieldName]; ok {
			return v, true
		}
	}
	return "", false
}

// EnvSource resolves values from environment variables named
// KRYPTOS_<SECRET>_<FIELD> and KRYPTOS_<FIELD> (upper-cased, non-alphanumerics
// → underscore). The qualified form wins. The lookup func is injected so it's
// testable without touching the real environment.
type EnvSource struct {
	Getenv func(string) string
}

// Lookup implements ValueSource.
func (e EnvSource) Lookup(secretName, fieldName string) (string, bool) {
	get := e.Getenv
	if get == nil {
		return "", false
	}
	if v := get("KRYPTOS_" + envKey(secretName) + "_" + envKey(fieldName)); v != "" {
		return v, true
	}
	if v := get("KRYPTOS_" + envKey(fieldName)); v != "" {
		return v, true
	}
	return "", false
}

// envKey upper-cases s and replaces every non-[A-Z0-9] rune with '_' so it's a
// valid environment-variable name component.
func envKey(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

// ChainSource tries each source in order, returning the first hit. Earlier
// sources win, so callers order them by precedence (e.g. --set, then --values,
// then env).
type ChainSource []ValueSource

// Lookup implements ValueSource.
func (c ChainSource) Lookup(secretName, fieldName string) (string, bool) {
	for _, s := range c {
		if v, ok := s.Lookup(secretName, fieldName); ok {
			return v, true
		}
	}
	return "", false
}
