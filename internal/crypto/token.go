package crypto

import (
	"errors"
	"strings"
	"uuid"
)

var ErrInvalidToken = errors.New("malformed token")

type Token struct {
	ID        string      // empty when no ID requested
	Plaintext string      // shown once
	Hash      HashedToken // hex-encoded
}

type ParsedToken struct {
	ID     string
	Secret string
}

type TokenOption func(*tokenConfig)

type tokenConfig struct {
	id string
}

// WithID binds the token to an id (a workspace id for enrollment and
// invitation tokens), so the plaintext is "id_secret" and Parse recovers the
// id from the token.
func WithID(id string) TokenOption {
	return func(c *tokenConfig) {
		c.id = id
	}
}

// NewSecret returns a fresh opaque secret and the hash to store. Only the
// hash is persisted; the raw secret is delivered to the client exactly once.
func NewSecret() (raw string, hash HashedToken, err error) {
	raw, err = RandomString(32)
	if err != nil {
		return "", "", err
	}
	hash, err = HashToken(raw)
	if err != nil {
		return "", "", err
	}
	return raw, hash, nil
}

// NewToken mints an opaque token. WithID binds the token to an id; without it
// the token is a bare secret.
func NewToken(opts ...TokenOption) (*Token, error) {
	cfg := &tokenConfig{}
	for _, o := range opts {
		o(cfg)
	}

	secret, err := RandomString(32)
	if err != nil {
		return nil, err
	}

	t := &Token{ID: cfg.id}

	var b strings.Builder
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

// Parse handles the token formats NewToken produces:
//
//	"uuid_secret" → {ID, Secret}
//	"secret"      → {Secret}
//
// A UUID is recognized in the first segment; everything after it is the
// secret (which may itself contain underscores).
func Parse(raw string) (*ParsedToken, error) {
	if raw == "" {
		return nil, ErrInvalidToken
	}

	id, secret, ok := strings.Cut(raw, "_")
	if !ok {
		return &ParsedToken{Secret: raw}, nil
	}
	if _, err := uuid.Parse(id); err != nil {
		return &ParsedToken{Secret: raw}, nil
	}
	return &ParsedToken{ID: id, Secret: secret}, nil
}
