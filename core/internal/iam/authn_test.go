package iam

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/cache"
)

func TestRequestCredential(t *testing.T) {
	tests := []struct {
		name          string
		authorization string
		want          string
	}{
		{"bearer", "Bearer tok", "tok"},
		{"dpop", "DPoP tok", "tok"},
		{"dpop lowercase", "dpop tok", "tok"},
		{"other scheme", "Basic tok", ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{}
			if tt.authorization != "" {
				header.Set("Authorization", tt.authorization)
			}
			if got := (&Service{}).requestCredential(header); got != tt.want {
				t.Fatalf("requestCredential() = %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("cookie", func(t *testing.T) {
		header := http.Header{}
		header.Add("Cookie", sessionCookieName+"=cookietok")
		if got := (&Service{}).requestCredential(header); got != "cookietok" {
			t.Fatalf("requestCredential() = %q, want cookietok", got)
		}
	})
}

func newTestVerifier(t *testing.T, now func() time.Time) *DPoPVerifier {
	t.Helper()
	return &DPoPVerifier{
		secret: []byte("test-secret"),
		replay: cache.New[[32]byte, struct{}](100, 3*dpopMaxSkew),
		now:    now,
	}
}

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
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	opts := (&jose.SignerOptions{}).WithType("dpop+jwt")
	opts.EmbedJWK = true
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: cryptosigner.Opaque(key)},
		opts,
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return compact
}

func TestVerifySessionProof(t *testing.T) {
	const (
		procedure = "/nokku.v1.UserService/Whoami"
		token     = "session-token"
		binding   = "test-jkt"
	)
	now := time.Unix(1_800_000_000, 0)
	svc := &Service{}
	svc.DPoP = newTestVerifier(t, func() time.Time { return now })
	ctx := actor.WithWorkspace(t.Context(), actor.Workspace{ID: "ws", BaseURL: "https://nokku.example.com"})
	htu := "https://nokku.example.com" + procedure

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	t.Run("valid bound proof", func(t *testing.T) {
		proof := signProof(t, key, htu, DPoPATH(token), svc.DPoP.CurrentNonce(), now)
		header := http.Header{}
		header.Set("Authorization", "DPoP "+token)
		header.Set("DPoP", proof)
		err := svc.verifySessionProof(ctx, header, procedure, token, binding)
		// The fixture binding cannot match. Anything but a binding mismatch means the proof itself failed.
		if err == nil {
			t.Fatal("expected a jkt mismatch for the fixture binding")
		}
		if !strings.Contains(err.Error(), "jkt mismatch") {
			t.Fatalf("verifySessionProof() = %v, want a jkt mismatch", err)
		}
	})

	t.Run("proof bound to the session key passes verification", func(t *testing.T) {
		jwk := &jose.JSONWebKey{Key: &key.PublicKey}
		tp, err := jwk.Thumbprint(crypto.SHA256)
		if err != nil {
			t.Fatalf("thumbprint: %v", err)
		}
		realBinding := base64.RawURLEncoding.EncodeToString(tp)

		proof := signProof(t, key, htu, DPoPATH(token), svc.DPoP.CurrentNonce(), now)
		header := http.Header{}
		header.Set("DPoP", proof)
		if err := svc.verifySessionProof(ctx, header, procedure, token, realBinding); err != nil {
			t.Fatalf("verifySessionProof() = %v, want nil", err)
		}
	})

	t.Run("missing proof is ErrDPoPRequired", func(t *testing.T) {
		header := http.Header{}
		header.Set("Authorization", "DPoP "+token)
		err := svc.verifySessionProof(ctx, header, procedure, token, binding)
		if err == nil || !errors.Is(err, ErrDPoPRequired) {
			t.Fatalf("verifySessionProof() = %v, want ErrDPoPRequired", err)
		}
	})

	t.Run("stale nonce maps to ErrDPoPNonce", func(t *testing.T) {
		proof := signProof(t, key, htu, DPoPATH(token), "stale-nonce", now)
		header := http.Header{}
		header.Set("DPoP", proof)
		err := svc.verifySessionProof(ctx, header, procedure, token, binding)
		if err == nil || !strings.Contains(err.Error(), "dpop nonce required") {
			t.Fatalf("verifySessionProof() = %v, want ErrDPoPNonce", err)
		}
	})
}

func TestSameHTU(t *testing.T) {
	const want = "https://nokku.example.com/nokku.v1.TargetService/GetMyAccess"
	tests := []struct {
		name  string
		claim string
		same  bool
	}{
		{"exact", want, true},
		{"host case and default port", "https://NOKKU.example.com:443/nokku.v1.TargetService/GetMyAccess", true},
		{"query and fragment do not count", want + "?x=1#y", true},
		{
			"doubled slash from a base with a trailing slash",
			"https://nokku.example.com//nokku.v1.TargetService/GetMyAccess",
			true,
		},
		{"other procedure", "https://nokku.example.com/nokku.v1.TargetService/ListTargets", false},
		{"path case", "https://nokku.example.com/nokku.v1.targetservice/getmyaccess", false},
		{"encoded slash", "https://nokku.example.com/nokku.v1.TargetService%2FGetMyAccess", false},
		{"other host", "https://evil.example.com/nokku.v1.TargetService/GetMyAccess", false},
		{"other port", "https://nokku.example.com:8443/nokku.v1.TargetService/GetMyAccess", false},
		{"other scheme", "http://nokku.example.com/nokku.v1.TargetService/GetMyAccess", false},
		{"not a url", "::", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sameHTU(tt.claim, want); got != tt.same {
				t.Fatalf("sameHTU(%q) = %v, want %v", tt.claim, got, tt.same)
			}
		})
	}
}

func TestAdvertiseDPoPNonce(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	svc := &Service{}
	svc.DPoP = newTestVerifier(t, func() time.Time { return now })
	ctx := actor.WithWorkspace(t.Context(), actor.Workspace{ID: "ws", BaseURL: "https://acme.nokku.example"})

	t.Run("sets nonce and the workspace url", func(t *testing.T) {
		header := http.Header{}
		svc.AdvertiseDPoPNonce(ctx, header)
		if header.Get("DPoP-Nonce") != svc.DPoP.CurrentNonce() {
			t.Error("AdvertiseDPoPNonce did not set the DPoP-Nonce header")
		}
		if header.Get(deviceURLHeader) != "https://acme.nokku.example" {
			t.Error("AdvertiseDPoPNonce did not set the canonical URL header")
		}
	})
}

// Anyone can send a proof without an access token, a flood must not get signed-in callers refused.
// Anyone can sign a proof without a session, so it never takes room in the replay store. What it is for, enrolling
// a daemon or polling a device grant, is single-use anyway.
func TestDPoPAnonymousProofsCannotFillTheSessionStore(t *testing.T) {
	const htu = "https://nokku.example.com/x"
	now := time.Unix(1_800_000_000, 0)
	v := newTestVerifier(t, func() time.Time { return now })
	v.replay = cache.New[[32]byte, struct{}](2, 3*dpopMaxSkew)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	verify := func(token string) error {
		ath := ""
		if token != "" {
			ath = DPoPATH(token)
		}
		proof := signProof(t, key, htu, ath, v.CurrentNonce(), now)
		_, err := v.Verify(proof, token, http.MethodPost, htu, "")
		return err
	}

	for range 10 {
		if err := verify(""); err != nil {
			t.Fatalf("anonymous proof: %v", err)
		}
	}
	for range 2 {
		if err := verify("session-token"); err != nil {
			t.Fatalf("session proof refused after an anonymous flood: %v", err)
		}
	}
}

// A valid token with someone else's key must not take room in the store every bound session shares.
func TestDPoPWrongKeyLeavesNoMarker(t *testing.T) {
	const htu, token = "https://nokku.example.com/x", "session-token"
	now := time.Unix(1_800_000_000, 0)
	v := newTestVerifier(t, func() time.Time { return now })
	v.replay = cache.New[[32]byte, struct{}](1, 3*dpopMaxSkew)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tp, err := (&jose.JSONWebKey{Key: &key.PublicKey}).Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	binding := base64.RawURLEncoding.EncodeToString(tp)
	proof := func() string { return signProof(t, key, htu, DPoPATH(token), v.CurrentNonce(), now) }

	verify := func(proof, binding string) error {
		_, err := v.Verify(proof, token, http.MethodPost, htu, binding)
		return err
	}

	if err := verify(proof(), "another-key"); !errors.Is(err, errBindingMismatch) {
		t.Fatalf("Verify() = %v, want a binding mismatch", err)
	}
	once := proof()
	if err := verify(once, binding); err != nil {
		t.Fatalf("the wrong key filled the store: %v", err)
	}
	if err := verify(once, binding); !errors.Is(err, errReplay) {
		t.Fatalf("replayed proof = %v, want errReplay", err)
	}
}

func TestDPoPProofRefusesTwoHeaders(t *testing.T) {
	h := http.Header{}
	if proof, err := DPoPProof(h); proof != "" || err != nil {
		t.Fatalf("DPoPProof() without a header = %q, %v", proof, err)
	}
	h.Add("DPoP", "a.b.c")
	if proof, err := DPoPProof(h); proof != "a.b.c" || err != nil {
		t.Fatalf("DPoPProof() = %q, %v, want a.b.c", proof, err)
	}
	h.Add("DPoP", "d.e.f")
	if _, err := DPoPProof(h); !errors.Is(err, errInvalidProof) {
		t.Fatalf("DPoPProof() with two headers: err = %v, want errInvalidProof", err)
	}
}
