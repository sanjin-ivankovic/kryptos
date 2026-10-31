package tui

import (
	"fmt"
	"strings"

	lipgloss "charm.land/lipgloss/v2"

	"source.example.com/example-org/kryptos/internal/config"
)

// printSummary renders the final results table to stdout.
func printSummary(results []Result) {
	successStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	errorStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	pathStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
	headerStyle := lipgloss.NewStyle().Bold(true).Underline(true).Foreground(lipgloss.Color("205"))
	nameStyle := lipgloss.NewStyle().Bold(true)

	fmt.Println()
	fmt.Println(headerStyle.Render("Generation Summary"))
	fmt.Println()

	for _, r := range results {
		if r.Err != nil {
			fmt.Printf("  %s %s\n    %s\n\n",
				errorStyle.Render("✗"),
				nameStyle.Render(r.DisplayName),
				errorStyle.Render(r.Err.Error()),
			)
		} else {
			fmt.Printf("  %s %s\n    %s\n\n",
				successStyle.Render("✓"),
				nameStyle.Render(r.DisplayName),
				pathStyle.Render(r.OutputPath),
			)
		}
	}
}

// printDryRun prints what would be generated without actually sealing or writing.
//
// Masking mirrors the input form's policy (fieldIsMasked): a field is masked
// unless its config sets `sensitive: false` explicitly. Keying off the config
// (not a substring heuristic on the field name) avoids leaking values whose key
// doesn't look secret — e.g. CSRF_KEY or apikey-style fields — and avoids
// over-masking benign ones.
func printDryRun(app *config.AppConfig, secret *config.Secret, data map[string]string) {
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	keyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("14"))

	// Build a key→sensitivity lookup from the secret's field definitions.
	// Keys absent from the map (e.g. static stringData) default to masked.
	sensitive := make(map[string]bool, len(secret.Fields))
	for _, f := range secret.Fields {
		sensitive[f.Name] = fieldIsMasked(f)
	}

	fmt.Println()
	fmt.Println(style.Render(fmt.Sprintf("[DRY RUN] %s/%s", app.Namespace, secret.Name)))
	for k, v := range data {
		shown := v
		mask, known := sensitive[k]
		if !known {
			mask = true // unknown key (static stringData): be safe, mask it
		}
		if mask {
			shown = maskValue(v)
		}
		fmt.Printf("  %s: %s\n", keyStyle.Render(k), shown)
	}
	fmt.Println()
}

// maskValue keeps the first 4 characters and stars out the rest, or returns a
// fixed "****" for short values so a length isn't leaked for tiny secrets.
func maskValue(v string) string {
	if len(v) > 4 {
		return v[:4] + strings.Repeat("*", len(v)-4)
	}
	return "****"
}
