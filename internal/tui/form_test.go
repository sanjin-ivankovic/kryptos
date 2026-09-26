package tui

import (
	"testing"

	"source.example.com/example-org/kryptos/internal/config"
)

func boolPtr(b bool) *bool { return &b }

func TestFieldIsMasked(t *testing.T) {
	cases := []struct {
		name  string
		field config.SecretField
		want  bool
	}{
		{"absent sensitive defaults to masked", config.SecretField{}, true},
		{"explicit sensitive:false unmasks", config.SecretField{Sensitive: boolPtr(false)}, false},
		{"explicit sensitive:true masks", config.SecretField{Sensitive: boolPtr(true)}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := fieldIsMasked(tc.field); got != tc.want {
				t.Errorf("fieldIsMasked = %v, want %v", got, tc.want)
			}
		})
	}
}
