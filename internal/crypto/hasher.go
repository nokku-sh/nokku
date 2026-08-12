package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Algorithm string

const (
	Argon2ID Algorithm = "argon2"
	SHA256   Algorithm = "sha256"

	// Argon2id parameters, targeted at ~250ms on modern hardware.
	// Memory is in KiB per the argon2 spec.
	argon2MemKiB  = 64 * 1024 // 64 MiB
	argon2Iter    = 2
	argon2Threads = 4
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

type Verifier interface {
	Digest(secret string) (string, error)
	Verify(secret, digest string) bool
}

type Hasher struct {
	algo Algorithm
}

func NewHasher(algo Algorithm) (*Hasher, error) {
	if !algo.ok() {
		return nil, fmt.Errorf("%s is not a hashing algorithm", algo)
	}
	return &Hasher{algo: algo}, nil
}

func (a Algorithm) ok() bool {
	switch a {
	case Argon2ID, SHA256:
		return true
	}
	return false
}

func (h *Hasher) Digest(secret string) (string, error) {
	switch h.algo {
	case SHA256:
		return h.hashSHA256(secret)
	case Argon2ID:
		return h.hashArgon2(secret)
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", h.algo)
	}
}

func (h *Hasher) Verify(secret, digest string) bool {
	switch h.algo {
	case SHA256:
		return h.verifySHA256(secret, digest)
	case Argon2ID:
		return h.verifyArgon2(secret, digest)
	default:
		return false
	}
}

func (h *Hasher) hashSHA256(secret string) (string, error) {
	hash := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(hash[:]), nil
}

func (h *Hasher) verifySHA256(secret, hash string) bool {
	checksum := sha256.Sum256([]byte(secret))
	decoded, err := hex.DecodeString(hash)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(checksum[:], decoded) == 1
}

func (h *Hasher) hashArgon2(secret string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(secret),
		salt,
		argon2Iter,
		argon2MemKiB,
		argon2Threads,
		argon2KeyLen,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2MemKiB,
		argon2Iter,
		argon2Threads,
		b64Salt,
		b64Hash,
	)

	return encoded, nil
}

func (h *Hasher) verifyArgon2(secret, encoded string) bool {
	// Expected format $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}

	params, err := parseArgon2Params(parts[3])
	if err != nil {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	expectedHashLen := len(expectedHash)
	// Guard against uint32 overflow when passing the length to argon2.IDKey.
	if expectedHashLen >= math.MaxUint32 {
		return false
	}

	computedHash := argon2.IDKey(
		[]byte(secret),
		salt,
		params.time,
		params.memory,
		params.threads,
		uint32(expectedHashLen),
	)

	return subtle.ConstantTimeCompare(computedHash, expectedHash) == 1
}

// Argon2 helper

type argon2Params struct {
	memory  uint32
	time    uint32
	threads uint8
}

func parseArgon2Params(s string) (argon2Params, error) {
	var p argon2Params

	for part := range strings.SplitSeq(s, ",") {
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			return p, fmt.Errorf("invalid param: %s", part)
		}

		valUint, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return p, err
		}

		switch key {
		case "m":
			p.memory = uint32(valUint)
		case "t":
			p.time = uint32(valUint)
		case "p":
			if valUint > math.MaxUint8 {
				return p, fmt.Errorf("invalid param: %s", part)
			}
			p.threads = uint8(valUint)
		}
	}

	if p.memory == 0 || p.time == 0 || p.threads == 0 {
		return p, fmt.Errorf("missing required params")
	}

	return p, nil
}
