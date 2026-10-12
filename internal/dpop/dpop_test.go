package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// TestATH verifies the access-token hash is base64url(SHA-256(token)).
func TestATH(t *testing.T) {
	// SHA-256("token"), base64url-encoded without padding.
	want := "PEaenWxYddN6Q_NT1PiOYfz4EsZu7jRXRlpAsNpBU-A"
	if got := ATH("token"); got != want {
		t.Fatalf("ATH = %q, want %q", got, want)
	}
}

// TestSignVerifiableProof signs a proof and verifies the compact JWS against
// the proofer's public key, checking the mandatory DPoP claims.
func TestSignVerifiableProof(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p, err := NewProofer(key, ProoferOptions{Now: func() time.Time { return time.Unix(1700000000, 0) }})
	if err != nil {
		t.Fatalf("NewProofer: %v", err)
	}

	token := "access-token"
	proof, err := p.Sign("POST", "https://api.example.com/nokku.v1.DaemonService/Connect", ATH(token), "server-nonce")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	jws, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	payload, err := jws.Verify(&jose.JSONWebKey{Key: &key.PublicKey})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	var claims map[string]any
	if err = json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("claims: %v", err)
	}
	if claims["htm"] != "POST" {
		t.Errorf("htm = %v, want POST", claims["htm"])
	}
	if claims["htu"] != "https://api.example.com/nokku.v1.DaemonService/Connect" {
		t.Errorf("htu = %v", claims["htu"])
	}
	if claims["nonce"] != "server-nonce" {
		t.Errorf("nonce = %v, want server-nonce", claims["nonce"])
	}
	if claims["ath"] != ATH(token) {
		t.Errorf("ath = %v, want %q", claims["ath"], ATH(token))
	}
	if int64(claims["iat"].(float64)) != 1700000000 {
		t.Errorf("iat = %v, want 1700000000", claims["iat"])
	}
	if claims["jti"] == "" {
		t.Error("jti is empty")
	}
}

// TestSignOmittedOptionals verifies ath and nonce are omitted when empty
// (enrollment proofs carry neither).
func TestSignOmittedOptionals(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p, err := NewProofer(key, ProoferOptions{})
	if err != nil {
		t.Fatalf("NewProofer: %v", err)
	}
	proof, err := p.Sign("POST", "https://api.example.com/enroll", "", "")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	jws, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	payload, err := jws.Verify(&jose.JSONWebKey{Key: &key.PublicKey})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var claims map[string]any
	if err = json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("claims: %v", err)
	}
	if _, ok := claims["ath"]; ok {
		t.Error("ath present, want omitted")
	}
	if _, ok := claims["nonce"]; ok {
		t.Error("nonce present, want omitted")
	}
}

// TestSignRejectsWrongKey verifies a proof does not verify under a different
// key, i.e. the JWK is actually bound into the signature.
func TestSignRejectsWrongKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p, err := NewProofer(key, ProoferOptions{})
	if err != nil {
		t.Fatalf("NewProofer: %v", err)
	}
	proof, err := p.Sign("GET", "https://api.example.com/x", "", "")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	jws, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	if _, err = jws.Verify(&jose.JSONWebKey{Key: &other.PublicKey}); err == nil {
		t.Fatal("proof verified under the wrong key")
	}
}

// TestNewProoferRejectsNonP256 verifies the proofer refuses keys other than
// ECDSA P-256.
func TestNewProoferRejectsNonP256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err = NewProofer(key, ProoferOptions{}); err == nil {
		t.Fatal("NewProofer accepted a P-384 key")
	}
}
