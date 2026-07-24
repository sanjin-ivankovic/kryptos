package cmd

import (
	"fmt"
	"sort"
	"strings"

	"source.example.com/example-org/kryptos/internal/config"
)

// emitDryRunPlain prints a dry-run preview for the non-interactive commands.
// Unlike the TUI's lipgloss renderer this is plain text (CI logs, no TTY), but
// it applies the same masking policy: a field is shown only when its config
// sets `sensitive: false`; everything else is masked. Keys absent from the
// field list (static stringData, derived siblings) default to masked.
func emitDryRunPlain(app *config.AppConfig, secret *config.Secret, data map[string]string) {
	masked := make(map[string]bool, len(secret.Fields))
	for _, f := range secret.Fields {
		masked[f.Name] = f.Sensitive == nil || *f.Sensitive
	}

	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fmt.Printf("[DRY RUN] %s/%s\n", app.Namespace, secret.Name)
	for _, k := range keys {
		show, known := masked[k]
		if !known {
			show = true
		}
		v := data[k]
		if show {
			v = maskValue(v)
		}
		fmt.Printf("  %s: %s\n", k, v)
	}
}

// maskValue keeps the first 4 characters and stars out the rest, or returns a
// fixed "****" for short values so a length isn't leaked for tiny secrets.
func maskValue(v string) string {
	if len(v) > 4 {
		return v[:4] + strings.Repeat("*", len(v)-4)
	}
	return "****"
}
