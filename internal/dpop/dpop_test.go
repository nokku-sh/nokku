package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func verifiedClaims(t *testing.T, proof string, pub *ecdsa.PublicKey) map[string]any {
	t.Helper()
	jws, err := jose.ParseSignedCompact(proof, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	payload, err := jws.Verify(&jose.JSONWebKey{Key: pub})
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

func TestATH(t *testing.T) {
	// SHA-256("token"), base64url-encoded without padding.
	assert.Equal(t, "PEaenWxYddN6Q_NT1PiOYfz4EsZu7jRXRlpAsNpBU-A", ATH("token"))
}

func TestSignVerifiableProof(t *testing.T) {
	// The bubble's clock stands still, so iat is exact.
	synctest.Test(t, func(t *testing.T) {
		key := testKey(t)
		p, err := NewProofer(key)
		require.NoError(t, err)

		const (
			token = "access-token"
			htu   = "https://api.example.com/nokku.v1.DaemonService/Connect"
		)
		proof, err := p.Sign("POST", htu, ATH(token), "server-nonce")
		require.NoError(t, err)

		claims := verifiedClaims(t, proof, &key.PublicKey)
		assert.Equal(t, "POST", claims["htm"])
		assert.Equal(t, htu, claims["htu"])
		assert.Equal(t, "server-nonce", claims["nonce"])
		assert.Equal(t, ATH(token), claims["ath"])
		assert.InDelta(t, time.Now().Unix(), claims["iat"], 0)
		assert.NotEmpty(t, claims["jti"])
	})
}

// Enrollment proofs carry neither ath nor nonce.
func TestSignOmittedOptionals(t *testing.T) {
	key := testKey(t)
	p, err := NewProofer(key)
	require.NoError(t, err)
	proof, err := p.Sign("POST", "https://api.example.com/enroll", "", "")
	require.NoError(t, err)

	claims := verifiedClaims(t, proof, &key.PublicKey)
	assert.NotContains(t, claims, "ath")
	assert.NotContains(t, claims, "nonce")
}

func TestNewProoferRejectsNonP256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	_, err = NewProofer(key)
	require.Error(t, err, "NewProofer accepted a P-384 key")
}
