//go:build integration

package iam_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/stretchr/testify/require"
)

// signProof produces a client-style DPoP proof with an ES256 key.
func signProof(
	t *testing.T,
	key *ecdsa.PrivateKey,
	htu, ath, nonce string,
	now time.Time,
) string {
	t.Helper()
	claims := map[string]any{
		"htm": http.MethodPost,
		"htu": htu,
		"iat": now.Unix(),
		"jti": rand.Text(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if ath != "" {
		claims["ath"] = ath
	}
	payload, err := json.Marshal(claims)
	require.NoError(t, err, "marshal claims")
	opts := (&jose.SignerOptions{}).WithType("dpop+jwt")
	opts.EmbedJWK = true
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: cryptosigner.Opaque(key)},
		opts,
	)
	require.NoError(t, err, "new signer")
	jws, err := signer.Sign(payload)
	require.NoError(t, err, "sign")
	compact, err := jws.CompactSerialize()
	require.NoError(t, err, "serialize")
	return compact
}
