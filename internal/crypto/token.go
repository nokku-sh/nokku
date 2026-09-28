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

// WithID makes the plaintext "id_secret" so Parse can recover the id.
func WithID(id string) TokenOption {
	return func(c *tokenConfig) {
		c.id = id
	}
}

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

// Parse handles "uuid_secret" and bare "secret". The secret may itself
// contain underscores.
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
