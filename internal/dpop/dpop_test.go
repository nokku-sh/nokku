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

// verifiedClaims checks the compact JWS against pub and returns its claims.
func verifiedClaims(t *testing.T, proof string, pub *ecdsa.PublicKey) map[string]any {
	t.Helper()
	jws, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	payload, err := jws.Verify(&jose.JSONWebKey{Key: pub})
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

// TestATH verifies the access-token hash is base64url(SHA-256(token)).
func TestATH(t *testing.T) {
	// SHA-256("token"), base64url-encoded without padding.
	assert.Equal(t, "PEaenWxYddN6Q_NT1PiOYfz4EsZu7jRXRlpAsNpBU-A", ATH("token"))
}

// TestSignVerifiableProof signs a proof and verifies the compact JWS against
// the proofer's public key, checking the mandatory DPoP claims.
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

// TestSignOmittedOptionals verifies ath and nonce are omitted when empty
// (enrollment proofs carry neither).
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

// TestSignRejectsWrongKey verifies a proof does not verify under a different
// key, i.e. the JWK is actually bound into the signature.
func TestSignRejectsWrongKey(t *testing.T) {
	p, err := NewProofer(testKey(t))
	require.NoError(t, err)
	proof, err := p.Sign("GET", "https://api.example.com/x", "", "")
	require.NoError(t, err)

	jws, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	_, err = jws.Verify(&jose.JSONWebKey{Key: &testKey(t).PublicKey})
	require.Error(t, err, "proof verified under the wrong key")
}

// TestNewProoferRejectsNonP256 verifies the proofer refuses keys other than
// ECDSA P-256.
func TestNewProoferRejectsNonP256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	_, err = NewProofer(key)
	require.Error(t, err, "NewProofer accepted a P-384 key")
}
