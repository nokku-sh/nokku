package crypto

import (
	"errors"
	"strings"
	"uuid"
)

var errInvalidToken = errors.New("malformed token")

type Token struct {
	ID        string      // empty when no ID requested
	Plaintext string      // shown once
	Hash      HashedToken // hex-encoded
}

type ParsedToken struct {
	ID     string
	Secret string
}

func NewSecret() (raw string, hash HashedToken) {
	raw = RandomString(32)
	return raw, HashToken(raw)
}

// NewToken with an id makes the plaintext "id_secret", so Parse can recover
// the id. An empty id gives a bare secret.
func NewToken(id string) *Token {
	plaintext := RandomString(32)
	if id != "" {
		plaintext = id + "_" + plaintext
	}
	return &Token{ID: id, Plaintext: plaintext, Hash: HashToken(plaintext)}
}

// Parse handles "uuid_secret" and bare "secret". The secret may itself
// contain underscores.
func Parse(raw string) (*ParsedToken, error) {
	if raw == "" {
		return nil, errInvalidToken
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
