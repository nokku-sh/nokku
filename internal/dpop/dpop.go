// Package dpop signs and verifies DPoP (RFC 9449) proofs. Every proof embeds
// the public JWK, so the core binds the session to the key's thumbprint (jkt)
// with no pre-registration.
package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
)

// Proofer needs a P-256 [crypto.Signer] that signs digests directly.
type Proofer struct {
	signer jose.Signer
}

func NewProofer(key crypto.Signer) (*Proofer, error) {
	pub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("dpop: signer must be an ECDSA P-256 key")
	}
	signerOpts := (&jose.SignerOptions{}).WithType("dpop+jwt")
	signerOpts.EmbedJWK = true
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: cryptosigner.Opaque(key)},
		signerOpts,
	)
	if err != nil {
		return nil, fmt.Errorf("dpop: build signer: %w", err)
	}
	return &Proofer{signer: signer}, nil
}

// ATH returns the base64url-encoded SHA-256 hash of token, the "ath" claim.
func ATH(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Sign takes "" for ath or nonce when there is none yet, as in enrollment.
func (p *Proofer) Sign(htm, htu, ath, nonce string) (string, error) {
	jti, err := newJTI()
	if err != nil {
		return "", fmt.Errorf("dpop: generate jti: %w", err)
	}
	claims := map[string]any{
		"htm": htm,
		"htu": htu,
		"iat": time.Now().Unix(),
		"jti": jti,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if ath != "" {
		claims["ath"] = ath
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	jws, err := p.signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("dpop: sign: %w", err)
	}
	return jws.CompactSerialize()
}

// A CSPRNG failure is fatal, a predictable jti would weaken replay detection.
func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
