package crypto

import (
	"errors"
	"hash/crc32"
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

// NewToken with an id makes the plaintext "id_secret", so Parse can recover the id.
func NewToken(id string) *Token {
	plaintext := RandomString(32)
	if id != "" {
		plaintext = id + "_" + plaintext
	}
	return &Token{ID: id, Plaintext: plaintext, Hash: HashToken(plaintext)}
}

// Parse handles "uuid_secret" and bare "secret". The secret may itself contain underscores.
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

const (
	KeyPrefixServiceAccount = "nk_sa_"
	KeyPrefixSCIM           = "nk_scim_"

	keyBodyBytes = 24 // 32 chars of base64url
	keyCheckLen  = 6  // base62 digits, enough for any crc32
)

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// NewKey makes "<prefix><random><checksum>". The checksum lets CheckKey reject a typo without a lookup.
func NewKey(prefix string) (raw string, hash HashedToken) {
	body := prefix + RandomString(keyBodyBytes)
	raw = body + keyCheck(body)
	return raw, HashToken(raw)
}

// HasKeyPrefix tells a key from a session secret, which is random and may start with "nk_".
func HasKeyPrefix(raw string) bool {
	return strings.HasPrefix(raw, KeyPrefixServiceAccount) || strings.HasPrefix(raw, KeyPrefixSCIM)
}

// CheckKey is a format check, not authentication.
func CheckKey(raw string) bool {
	if len(raw) <= keyCheckLen || !strings.HasPrefix(raw, "nk_") {
		return false
	}
	body, check := raw[:len(raw)-keyCheckLen], raw[len(raw)-keyCheckLen:]
	return keyCheck(body) == check
}

func keyCheck(body string) string {
	n := crc32.ChecksumIEEE([]byte(body))
	var out [keyCheckLen]byte
	for i := keyCheckLen - 1; i >= 0; i-- {
		out[i] = base62[n%62]
		n /= 62
	}
	return string(out[:])
}
