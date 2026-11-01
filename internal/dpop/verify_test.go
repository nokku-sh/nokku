package dpop

import (
	"crypto"
	"encoding/base64"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestVerifier drops the oldest jti past size, like the core's store.
func newTestVerifier(size int) *Verifier {
	var seen [][32]byte
	return NewVerifier([]byte("test-secret"), func(jti [32]byte) bool {
		if slices.Contains(seen, jti) {
			return false
		}
		seen = append(seen, jti)
		if len(seen) > size {
			seen = seen[1:]
		}
		return true
	}, time.Now)
}

func testProof(t *testing.T, p *Proofer, htu, token, nonce string) string {
	t.Helper()
	ath := ""
	if token != "" {
		ath = ATH(token)
	}
	proof, err := p.Sign(http.MethodPost, htu, ath, nonce)
	require.NoError(t, err)
	return proof
}

func TestVerify(t *testing.T) {
	const htu, token = "https://nokku.example.com/nokku.v1.UserService/Whoami", "session-token"
	key := testKey(t)
	p, err := NewProofer(key)
	require.NoError(t, err)
	tp, err := (&jose.JSONWebKey{Key: &key.PublicKey}).Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	binding := base64.RawURLEncoding.EncodeToString(tp)
	v := newTestVerifier(100)

	jkt, err := v.Verify(testProof(t, p, htu, token, v.CurrentNonce()), token, http.MethodPost, htu, binding)
	require.NoError(t, err)
	assert.Equal(t, binding, jkt)

	_, err = v.Verify(testProof(t, p, htu, token, "stale-nonce"), token, http.MethodPost, htu, binding)
	require.ErrorIs(t, err, ErrNonce)
	_, err = v.Verify(testProof(t, p, htu, "other-token", v.CurrentNonce()), token, http.MethodPost, htu, binding)
	require.ErrorIs(t, err, ErrInvalidProof, "a proof for another token")
	_, err = v.Verify(testProof(t, p, htu, token, v.CurrentNonce()), token, http.MethodGet, htu, binding)
	require.ErrorIs(t, err, ErrInvalidProof, "a proof for another method")
	_, err = v.Verify(testProof(t, p, htu+"x", token, v.CurrentNonce()), token, http.MethodPost, htu, binding)
	require.ErrorIs(t, err, ErrInvalidProof, "a proof for another URL")
	_, err = v.Verify("a.b.c", token, http.MethodPost, htu, binding)
	require.ErrorIs(t, err, ErrInvalidProof, "not a proof")
}

func TestVerifyTakesOnlyTheCompactForm(t *testing.T) {
	const htu = "https://nokku.example.com/x"
	v := newTestVerifier(1)
	p, err := NewProofer(testKey(t))
	require.NoError(t, err)
	proof := testProof(t, p, htu, "", v.CurrentNonce())
	_, err = v.Verify(proof, "", http.MethodPost, htu, "")
	require.NoError(t, err)

	jws, err := jose.ParseSignedCompact(proof, allowedAlgs)
	require.NoError(t, err)
	_, err = v.Verify(jws.FullSerialize(), "", http.MethodPost, htu, "")
	require.ErrorIs(t, err, ErrInvalidProof, "the same proof as JSON")
}

// Anyone can sign a proof without a session, so it takes no room in the replay
// store. Enrolling and device polls are single-use anyway.
func TestAnonymousProofsCannotFillTheSessionStore(t *testing.T) {
	const htu = "https://nokku.example.com/x"
	v := newTestVerifier(2)
	p, err := NewProofer(testKey(t))
	require.NoError(t, err)
	verify := func(token string) error {
		_, verr := v.Verify(testProof(t, p, htu, token, v.CurrentNonce()), token, http.MethodPost, htu, "")
		return verr
	}

	for range 10 {
		require.NoError(t, verify(""), "anonymous proof")
	}
	for range 2 {
		require.NoError(t, verify("session-token"), "session proof refused after an anonymous flood")
	}
}

// A valid token with the wrong key must take no room in the shared store.
func TestWrongKeyLeavesNoMarker(t *testing.T) {
	const htu, token = "https://nokku.example.com/x", "session-token"
	v := newTestVerifier(1)
	key := testKey(t)
	p, err := NewProofer(key)
	require.NoError(t, err)
	tp, err := (&jose.JSONWebKey{Key: &key.PublicKey}).Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	binding := base64.RawURLEncoding.EncodeToString(tp)
	verify := func(proof, binding string) error {
		_, verr := v.Verify(proof, token, http.MethodPost, htu, binding)
		return verr
	}

	require.ErrorIs(t, verify(testProof(t, p, htu, token, v.CurrentNonce()), "another-key"), errBindingMismatch)
	once := testProof(t, p, htu, token, v.CurrentNonce())
	require.NoError(t, verify(once, binding), "the wrong key filled the store")
	require.ErrorIs(t, verify(once, binding), errReplay)
}

func TestProofFromRefusesTwoHeaders(t *testing.T) {
	h := http.Header{}
	proof, err := ProofFrom(h)
	require.NoError(t, err)
	assert.Empty(t, proof)
	h.Add("DPoP", "a.b.c")
	proof, err = ProofFrom(h)
	require.NoError(t, err)
	assert.Equal(t, "a.b.c", proof)
	h.Add("DPoP", "d.e.f")
	_, err = ProofFrom(h)
	require.ErrorIs(t, err, ErrInvalidProof)
}

func TestSameURL(t *testing.T) {
	const want = "https://nokku.example.com/nokku.v1.TargetService/GetSubjectAccess"
	for name, tc := range map[string]struct {
		url  string
		same bool
	}{
		"exact":                           {want, true},
		"host case and default port":      {"https://NOKKU.example.com:443/nokku.v1.TargetService/GetSubjectAccess", true},
		"query and fragment do not count": {want + "?x=1#y", true},
		"doubled slash from a base with a trailing slash": {
			"https://nokku.example.com//nokku.v1.TargetService/GetSubjectAccess", true,
		},
		"other procedure": {"https://nokku.example.com/nokku.v1.TargetService/ListTargets", false},
		"path case":       {"https://nokku.example.com/nokku.v1.targetservice/getmyaccess", false},
		"encoded slash":   {"https://nokku.example.com/nokku.v1.TargetService%2FGetSubjectAccess", false},
		"other host":      {"https://evil.example.com/nokku.v1.TargetService/GetSubjectAccess", false},
		"other port":      {"https://nokku.example.com:8443/nokku.v1.TargetService/GetSubjectAccess", false},
		"other scheme":    {"http://nokku.example.com/nokku.v1.TargetService/GetSubjectAccess", false},
		"not a url":       {"::", false},
	} {
		assert.Equal(t, tc.same, SameURL(tc.url, want), name)
	}

	const base = "https://api.example.com"
	for name, tc := range map[string]struct {
		url  string
		same bool
	}{
		"trailing slash": {base + "/", true},
		"default port":   {"https://api.example.com:443", true},
		"path prefix":    {base + "/nokku", false},
	} {
		assert.Equal(t, tc.same, SameURL(tc.url, base), name)
	}
}
