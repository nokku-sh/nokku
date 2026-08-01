package crypto

import (
	"errors"
	"strings"
	"testing"
)

func TestNewToken_NoOptions(t *testing.T) {
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}

	if tok.ID != "" {
		t.Errorf("ID = %q, want empty", tok.ID)
	}

	// The secret uses base64url, which may itself contain underscores; a
	// bare token round-trips through Parse as a bare secret.
	parsed, err := Parse(tok.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Secret != tok.Plaintext || parsed.ID != "" || parsed.Prefix != "" {
		t.Errorf("Parse() = %+v, want bare secret", parsed)
	}
	if !tok.Hash.Verify(tok.Plaintext) {
		t.Error("hash does not verify against plaintext")
	}
}

func TestNewToken_WithPrefix(t *testing.T) {
	tok, err := NewToken(WithPrefix(PrefixDaemon))
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(tok.Plaintext, PrefixDaemon+"_") {
		t.Errorf("plaintext %q missing prefix", tok.Plaintext)
	}
	parts := strings.Split(tok.Plaintext, "_")
	if len(parts) < 3 {
		t.Fatalf("plaintext %q should be prefix_id_secret", tok.Plaintext)
	}

	parsed, err := Parse(tok.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Prefix != PrefixDaemon {
		t.Errorf("Prefix = %q, want %q", parsed.Prefix, PrefixDaemon)
	}
	// The secret is base64url and may contain underscores; Parse must
	// rejoin everything after the ID.
	wantSecret := strings.Join(parts[2:], "_")
	if parsed.ID != tok.ID || parsed.Secret != wantSecret {
		t.Errorf("Parse() = %+v, want id %q secret %q", parsed, tok.ID, wantSecret)
	}
	if !tok.Hash.Verify(tok.Plaintext) {
		t.Error("hash does not verify")
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
	if parsed.Prefix != "" {
		t.Errorf("Parse().Prefix = %q, want empty", parsed.Prefix)
	}
}

func TestNewToken_WithNonUUIDID_NotRecoverableByParse(t *testing.T) {
	// Parse only recognizes UUIDs as IDs; a custom non-UUID ID is stored
	// in the plaintext but cannot be recovered (documented limitation).
	tok, err := NewToken(WithID("custom-id"))
	if err != nil {
		t.Fatal(err)
	}
	if tok.ID != "custom-id" {
		t.Errorf("ID = %q, want custom-id", tok.ID)
	}
	parsed, err := Parse(tok.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ID != "" || parsed.Prefix != "" {
		t.Errorf("Parse() = %+v, want bare secret fallback", parsed)
	}
}

func TestNewToken_ConvenienceConstructors(t *testing.T) {
	tests := []struct {
		name   string
		got    *Token
		prefix string
	}{
		{"daemon", mustNewToken(NewDaemonToken()), PrefixDaemon},
		{"service account", mustNewToken(NewServiceAccountToken()), PrefixSA},
		{"cli", mustNewToken(NewCLIToken()), PrefixCLI},
		{"device", mustNewToken(NewDeviceToken()), PrefixDevice},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.HasPrefix(tt.got.Plaintext, tt.prefix+"_") {
				t.Errorf("plaintext %q missing prefix %q", tt.got.Plaintext, tt.prefix)
			}
		})
	}
}

func mustNewToken(tok *Token, err error) *Token {
	if err != nil {
		panic(err)
	}
	return tok
}

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want ParsedToken
	}{
		{"bare secret", "supersecret", ParsedToken{Secret: "supersecret"}},
		{"uuid + secret", "123e4567-e89b-12d3-a456-426614174000_mys3cr3t",
			ParsedToken{ID: "123e4567-e89b-12d3-a456-426614174000", Secret: "mys3cr3t"}},
		{"two segments without uuid treated as bare secret",
			"notauuid_part", ParsedToken{Secret: "notauuid_part"}},
		{
			"prefix + uuid + secret",
			"nkd_123e4567-e89b-12d3-a456-426614174000_s3cr3t",
			ParsedToken{
				Prefix: "nkd",
				ID:     "123e4567-e89b-12d3-a456-426614174000",
				Secret: "s3cr3t",
			},
		},
		{
			"prefix + uuid + secret with underscores in secret",
			"nkd_123e4567-e89b-12d3-a456-426614174000_a_b_c",
			ParsedToken{
				Prefix: "nkd",
				ID:     "123e4567-e89b-12d3-a456-426614174000",
				Secret: "a_b_c",
			},
		},
		{"uuid + secret with underscores in secret",
			"123e4567-e89b-12d3-a456-426614174000_a_b",
			ParsedToken{ID: "123e4567-e89b-12d3-a456-426614174000", Secret: "a_b"}},
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
	if _, err := Parse(""); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Parse(\"\") error = %v, want ErrInvalidToken", err)
	}
}

func TestTokenHash_Verification(t *testing.T) {
	tok, err := NewToken(WithPrefix(PrefixCLI))
	if err != nil {
		t.Fatal(err)
	}

	if tok.Hash.IsZero() {
		t.Error("Hash is zero")
	}
	if !tok.Hash.Verify(tok.Plaintext) {
		t.Error("Verify() with correct plaintext: want true")
	}
	if tok.Hash.Verify("wrong") {
		t.Error("Verify() with wrong plaintext: want false")
	}
	if tok.Hash.Verify(tok.Plaintext + "x") {
		t.Error("Verify() with near-miss plaintext: want false")
	}
}
