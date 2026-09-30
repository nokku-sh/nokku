package crypto

import (
	"errors"
	"strings"
	"testing"
)

func TestNewToken_NoID(t *testing.T) {
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}

	if tok.ID != "" {
		t.Errorf("ID = %q, want empty", tok.ID)
	}

	// A bare token is a bare secret: Parse returns it as the Secret.
	parsed, err := Parse(tok.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Secret != tok.Plaintext || parsed.ID != "" {
		t.Errorf("Parse() = %+v, want bare secret", parsed)
	}
	if want, _ := HashToken(tok.Plaintext); tok.Hash != want {
		t.Error("hash does not match the plaintext")
	}
}

func TestNewToken_WithID(t *testing.T) {
	id := "123e4567-e89b-12d3-a456-426614174000" // UUID-form ID round-trips through Parse
	tok, err := NewToken(WithID(id))
	if err != nil {
		t.Fatal(err)
	}
	if tok.ID != id {
		t.Errorf("ID = %q, want %q", tok.ID, id)
	}
	if !strings.HasPrefix(tok.Plaintext, id+"_") {
		t.Errorf("plaintext %q missing id prefix", tok.Plaintext)
	}

	parsed, err := Parse(tok.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ID != id {
		t.Errorf("Parse().ID = %q, want %q", parsed.ID, id)
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want ParsedToken
	}{
		{"bare secret", "supersecret", ParsedToken{Secret: "supersecret"}},
		{
			"uuid + secret", "123e4567-e89b-12d3-a456-426614174000_mys3cr3t",
			ParsedToken{ID: "123e4567-e89b-12d3-a456-426614174000", Secret: "mys3cr3t"},
		},
		{
			"non-uuid first segment treated as bare secret",
			"notauuid_part",
			ParsedToken{Secret: "notauuid_part"},
		},
		{
			"uuid + secret with underscores in secret",
			"123e4567-e89b-12d3-a456-426614174000_a_b",
			ParsedToken{ID: "123e4567-e89b-12d3-a456-426614174000", Secret: "a_b"},
		},
		{"bare secret containing underscores", "a_b_c", ParsedToken{Secret: "a_b_c"}},
		{"bare secret containing many underscores", "a_b_c_d_e", ParsedToken{Secret: "a_b_c_d_e"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.in)
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", tt.in, err)
			}
			if *got != tt.want {
				t.Errorf("Parse(%q) = %+v, want %+v", tt.in, *got, tt.want)
			}
		})
	}
}

func TestParse_Empty(t *testing.T) {
	if _, err := Parse(""); !errors.Is(err, errInvalidToken) {
		t.Errorf("Parse(\"\") error = %v, want errInvalidToken", err)
	}
}
