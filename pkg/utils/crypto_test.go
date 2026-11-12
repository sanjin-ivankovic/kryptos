package utils

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// ambiguousChars are the glyphs GenerateSecurePassword deliberately omits so a
// human reading a password aloud can't confuse 0/O or 1/l/I.
const ambiguousChars = "0O1lI"

func TestGenerateSecurePassword(t *testing.T) {
	t.Run("honours length floor", func(t *testing.T) {
		// Requesting fewer than minPasswordLength (8) is clamped up, not down.
		for _, req := range []int{0, 1, 7} {
			got, err := GenerateSecurePassword(req, false)
			if err != nil {
				t.Fatalf("req=%d: unexpected error: %v", req, err)
			}
			if len(got) < minPasswordLength {
				t.Errorf("req=%d: length %d below floor %d", req, len(got), minPasswordLength)
			}
		}
	})

	t.Run("returns requested length when above floor", func(t *testing.T) {
		for _, req := range []int{8, 16, 32, 64} {
			got, err := GenerateSecurePassword(req, false)
			if err != nil {
				t.Fatalf("req=%d: unexpected error: %v", req, err)
			}
			if len(got) != req {
				t.Errorf("req=%d: got length %d", req, len(got))
			}
		}
	})

	t.Run("excludes ambiguous characters", func(t *testing.T) {
		// Generate many passwords; none should contain a confusable glyph.
		for range 200 {
			got, err := GenerateSecurePassword(32, true)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.ContainsAny(got, ambiguousChars) {
				t.Fatalf("password %q contains an ambiguous character", got)
			}
		}
	})

	t.Run("contains at least one of each required class", func(t *testing.T) {
		const lower = "abcdefghjkmnpqrstuvwxyz"
		const upper = "ABCDEFGHJKMNPQRSTUVWXYZ"
		const digits = "23456789"
		for range 200 {
			got, err := GenerateSecurePassword(12, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.ContainsAny(got, lower) {
				t.Fatalf("password %q has no lowercase", got)
			}
			if !strings.ContainsAny(got, upper) {
				t.Fatalf("password %q has no uppercase", got)
			}
			if !strings.ContainsAny(got, digits) {
				t.Fatalf("password %q has no digit", got)
			}
		}
	})

	t.Run("includes symbols only when requested", func(t *testing.T) {
		const symbols = "!@#$%^&*"

		// Without symbols: never any, across many samples.
		for range 200 {
			got, err := GenerateSecurePassword(32, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.ContainsAny(got, symbols) {
				t.Fatalf("password %q contains a symbol but symbols were disabled", got)
			}
		}

		// With symbols: guaranteed at least one (the generator seeds buf[3]).
		for range 200 {
			got, err := GenerateSecurePassword(32, true)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.ContainsAny(got, symbols) {
				t.Fatalf("password %q has no symbol but symbols were enabled", got)
			}
		}
	})

	t.Run("produces distinct values", func(t *testing.T) {
		seen := make(map[string]bool)
		for range 100 {
			got, err := GenerateSecurePassword(32, true)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if seen[got] {
				t.Fatalf("duplicate password generated: %q", got)
			}
			seen[got] = true
		}
	})
}

func TestGenerateAPIKey(t *testing.T) {
	t.Run("is valid hex of the requested length", func(t *testing.T) {
		for _, length := range []int{16, 32, 64} {
			got, err := GenerateAPIKey(length)
			if err != nil {
				t.Fatalf("length=%d: unexpected error: %v", length, err)
			}
			if len(got) != length {
				t.Errorf("length=%d: got %d chars", length, len(got))
			}
			if _, err := hex.DecodeString(got); err != nil {
				t.Errorf("length=%d: not valid hex: %v", length, err)
			}
		}
	})

	t.Run("odd length truncates to floor(length/2) bytes", func(t *testing.T) {
		// length/2 integer division: an odd request yields one fewer hex char.
		got, err := GenerateAPIKey(7)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 6 {
			t.Errorf("odd length 7 should yield 6 hex chars, got %d (%q)", len(got), got)
		}
	})

	t.Run("produces distinct values", func(t *testing.T) {
		seen := make(map[string]bool)
		for range 100 {
			got, err := GenerateAPIKey(64)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if seen[got] {
				t.Fatalf("duplicate API key generated: %q", got)
			}
			seen[got] = true
		}
	})
}

func TestGenerateBase64Key(t *testing.T) {
	t.Run("round-trips to the requested byte length", func(t *testing.T) {
		for _, n := range []int{1, 16, 32, 48} {
			got, err := GenerateBase64Key(n)
			if err != nil {
				t.Fatalf("n=%d: unexpected error: %v", n, err)
			}
			decoded, err := base64.StdEncoding.DecodeString(got)
			if err != nil {
				t.Fatalf("n=%d: not valid base64: %v", n, err)
			}
			if len(decoded) != n {
				t.Errorf("n=%d: decoded to %d bytes", n, len(decoded))
			}
		}
	})

	t.Run("produces distinct values", func(t *testing.T) {
		seen := make(map[string]bool)
		for range 100 {
			got, err := GenerateBase64Key(32)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if seen[got] {
				t.Fatalf("duplicate base64 key generated: %q", got)
			}
			seen[got] = true
		}
	})
}

func TestGenerateHtpasswd(t *testing.T) {
	t.Run("requires username", func(t *testing.T) {
		if _, err := GenerateHtpasswd("", "pw"); err == nil {
			t.Fatal("expected error for empty username")
		}
	})

	t.Run("requires password", func(t *testing.T) {
		if _, err := GenerateHtpasswd("user", ""); err == nil {
			t.Fatal("expected error for empty password")
		}
	})

	t.Run("emits user:bcrypt and the hash verifies", func(t *testing.T) {
		const user, pass = "harbor_registry_user", "s3cr3t-password"
		got, err := GenerateHtpasswd(user, pass)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		prefix, hash, found := strings.Cut(got, ":")
		if !found {
			t.Fatalf("output %q is not in user:hash form", got)
		}
		if prefix != user {
			t.Errorf("username component = %q, want %q", prefix, user)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)); err != nil {
			t.Errorf("bcrypt hash does not verify against the password: %v", err)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrong")); err == nil {
			t.Error("bcrypt hash verified against the wrong password")
		}
	})
}

func TestGeneratePassphrase(t *testing.T) {
	t.Run("produces the requested word count joined by the separator", func(t *testing.T) {
		cases := []struct {
			count int
			sep   string
		}{
			{1, "-"},
			{4, "-"},
			{4, "_"},
			{6, "."},
		}
		for _, tc := range cases {
			got, err := GeneratePassphrase(tc.count, tc.sep)
			if err != nil {
				t.Fatalf("count=%d sep=%q: unexpected error: %v", tc.count, tc.sep, err)
			}
			parts := strings.Split(got, tc.sep)
			if len(parts) != tc.count {
				t.Errorf("count=%d sep=%q: got %d words (%q)", tc.count, tc.sep, len(parts), got)
			}
			for _, p := range parts {
				if p == "" {
					t.Errorf("count=%d sep=%q: produced an empty word in %q", tc.count, tc.sep, got)
				}
			}
		}
	})
}
