package util

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateUsername(t *testing.T) {
	tests := []struct {
		name      string
		email     string
		username  string
		fallbacks []string
		want      string
	}{
		{
			name:     "preferred username wins",
			email:    "jane@example.com",
			username: "jane-dev",
			want:     "jane-dev",
		},
		{
			name:  "email local part fallback",
			email: "jane.doe@example.com",
			want:  "jane.doe",
		},
		{
			name:     "username with invalid chars sanitized",
			email:    "x@example.com",
			username: "Jane Doe!@#",
			want:     "jane.doe",
		},
		{
			name:     "leading/trailing separators trimmed",
			email:    "x@example.com",
			username: "--jane--",
			want:     "jane",
		},
		{
			name:     "repeated separators collapsed",
			email:    "x@example.com",
			username: "a..b--c__d",
			want:     "a.b.c.d",
		},
		{
			name:      "fallback sanitized (@ is dropped, not split)",
			fallbacks: []string{"ops@acme.io"},
			want:      "opsacme.io",
		},
		{
			name:      "fallback with invalid chars sanitized",
			fallbacks: []string{" Ops! "},
			want:      "ops",
		},
		{
			name:      "hashed fallback when nothing valid",
			email:     "@",
			fallbacks: []string{"!!!"},
			want:      "user-" + hashPrefix("@"),
		},
		{
			name:      "empty email with empty fallback list errors",
			fallbacks: []string{},
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateUsername(tt.email, tt.username, tt.fallbacks)
			if tt.want == "" {
				if err == nil {
					t.Fatalf("GenerateUsername() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("GenerateUsername() error: %v", err)
			}
			if got != tt.want {
				t.Errorf("GenerateUsername() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenerateUsername_LongInputs(t *testing.T) {
	got, err := GenerateUsername(strings.Repeat("a", 300)+"@example.com", "", nil)
	if err != nil {
		t.Fatalf("GenerateUsername() error: %v", err)
	}
	if len(got) > 64 {
		t.Errorf("username %q exceeds 64 chars", got)
	}
	if !strings.HasSuffix(got, "a") {
		t.Errorf("username %q should not end with a separator", got)
	}
}

func TestGenerateUsername_DeterministicHash(t *testing.T) {
	first, err := GenerateUsername("@", "", []string{"!!!"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateUsername("@", "", []string{"!!!"})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("hashed usernames differ across calls: %q vs %q", first, second)
	}
	if !strings.HasPrefix(first, "user-") {
		t.Errorf("hashed username %q missing prefix", first)
	}
}

func hashPrefix(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])[:12]
}
