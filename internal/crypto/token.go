package crypto

import (
	"errors"
	"strings"

	"github.com/google/uuid"
)

const (
	PrefixDaemon = "nkd"
	PrefixSA     = "nks"
	PrefixCLI    = "nkc"
	PrefixDevice = "nkv"
)

var ErrInvalidToken = errors.New("malformed token")

type Token struct {
	ID        string      // empty when no ID requested
	Plaintext string      // shown once
	Hash      HashedToken // hex-encoded
}

type ParsedToken struct {
	Prefix string
	ID     string
	Secret string
}

type TokenOption func(*tokenConfig)

type tokenConfig struct {
	prefix string
	id     string
	withID bool // explicitly request an ID (generated or supplied)
}

func WithPrefix(p string) TokenOption {
	return func(c *tokenConfig) {
		c.prefix = p
		c.withID = true // prefix implies ID
	}
}

func WithID(id string) TokenOption {
	return func(c *tokenConfig) {
		c.id = id
		c.withID = true
	}
}

func NewToken(opts ...TokenOption) (*Token, error) {
	cfg := &tokenConfig{}
	for _, o := range opts {
		o(cfg)
	}

	secret, err := RandomString(32)
	if err != nil {
		return nil, err
	}

	t := &Token{}

	switch {
	case cfg.id != "":
		t.ID = cfg.id
	case cfg.withID:
		uid, err := uuid.NewV7()
		if err != nil {
			return nil, err
		}
		t.ID = uid.String()
	}

	// Build plaintext: "prefix_id_secret" | "id_secret" | "secret"
	var b strings.Builder
	if cfg.prefix != "" {
		b.WriteString(cfg.prefix)
		b.WriteByte('_')
	}
	if t.ID != "" {
		b.WriteString(t.ID)
		b.WriteByte('_')
	}
	b.WriteString(secret)

	t.Plaintext = b.String()
	t.Hash, err = HashToken(t.Plaintext)
	if err != nil {
		return nil, err
	}

	return t, nil
}

// Convenience constructors

func NewServiceAccountToken() (*Token, error) {
	return NewToken(WithPrefix(PrefixSA))
}

func NewDeviceToken() (*Token, error) {
	return NewToken(WithPrefix(PrefixDevice))
}

// Parse handles all three formats:
//
//	"prefix_uuid_secret" → {Prefix, ID, Secret}
//	"uuid_secret"        → {ID, Secret}
//	"secret"             → {Secret}
func Parse(raw string) (*ParsedToken, error) {
	if raw == "" {
		return nil, ErrInvalidToken
	}

	parts := strings.Split(raw, "_")

	switch len(parts) {
	case 1:
		return &ParsedToken{Secret: raw}, nil

	case 2:
		if _, err := uuid.Parse(parts[0]); err == nil {
			return &ParsedToken{ID: parts[0], Secret: parts[1]}, nil
		}
		// Otherwise treat entire string as bare secret
		return &ParsedToken{Secret: raw}, nil

	default:
		// 3+ segments: try "prefix_uuid_rest" first
		if _, err := uuid.Parse(parts[1]); err == nil {
			return &ParsedToken{
				Prefix: parts[0],
				ID:     parts[1],
				Secret: strings.Join(parts[2:], "_"),
			}, nil
		}
		// Try "uuid_rest" (UUID contains no underscores, so parts[0])
		if _, err := uuid.Parse(parts[0]); err == nil {
			return &ParsedToken{
				ID:     parts[0],
				Secret: strings.Join(parts[1:], "_"),
			}, nil
		}
		// Bare secret that happens to contain underscores
		return &ParsedToken{Secret: raw}, nil
	}
}
