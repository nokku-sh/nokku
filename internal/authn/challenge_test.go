package authn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strconv"
	"testing"
)

func TestChallengeRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	const (
		daemonID  = "123e4567-e89b-12d3-a456-426614174000"
		ts        = "1700000000"
		nonce     = "deadbeefcafebabe"
		procedure = "/nokku.v1.DaemonService/SyncDaemon"
	)
	payload := daemonID + ":" + ts + ":" + nonce + ":" + procedure
	digest := sha256.Sum256([]byte(payload))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	raw := payload + ":" + base64.RawURLEncoding.EncodeToString(sig)
	chal, err := ParseChallenge(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if chal.DaemonID != daemonID || chal.Procedure != procedure || chal.Nonce != nonce {
		t.Fatalf("parsed challenge mismatch: %+v", chal)
	}
	if got := strconv.FormatInt(chal.Timestamp, 10); got != ts {
		t.Fatalf("timestamp = %s, want %s", got, ts)
	}
	if err := chal.Verify(pubPEM); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestChallengeVerifyFailures(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	sign := func(payload string) string {
		digest := sha256.Sum256([]byte(payload))
		sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return payload + ":" + base64.RawURLEncoding.EncodeToString(sig)
	}

	const base = "123e4567-e89b-12d3-a456-426614174000:1700000000:deadbeef:procedure"

	t.Run("wrong procedure", func(t *testing.T) {
		// Signed for a different RPC than the one being invoked.
		raw := sign(base)
		chal, err := ParseChallenge(raw)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		chal.Procedure = "other"
		if err := chal.Verify(pubPEM); err == nil {
			t.Fatal("expected verification failure")
		}
	})

	t.Run("tampered signature", func(t *testing.T) {
		raw := sign(base)
		chal, _ := ParseChallenge(raw)
		chal.Signature[0] ^= 0xff
		if err := chal.Verify(pubPEM); err == nil {
			t.Fatal("expected verification failure")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		otherDER, err := x509.MarshalPKIXPublicKey(&other.PublicKey)
		if err != nil {
			t.Fatalf("marshal pubkey: %v", err)
		}
		raw := sign(base)
		chal, _ := ParseChallenge(raw)
		otherPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherDER})
		if err := chal.Verify(otherPEM); err == nil {
			t.Fatal("expected verification failure")
		}
	})

	t.Run("nonce mutates signature", func(t *testing.T) {
		raw := sign(base)
		chal, _ := ParseChallenge(raw)
		chal.Nonce = "beef"
		if err := chal.Verify(pubPEM); err == nil {
			t.Fatal("expected verification failure")
		}
	})
}

func TestParseChallengeMalformed(t *testing.T) {
	cases := []string{
		"",
		"no-colons-here",
		"not-a-uuid:1700000000:nonce:procedure:c2ln",
		"123e4567-e89b-12d3-a456-426614174000:nope:nonce:procedure:c2ln",
		"123e4567-e89b-12d3-a456-426614174000:1700000000::procedure:c2ln",
		"123e4567-e89b-12d3-a456-426614174000:1700000000:nonce::c2ln",
		"123e4567-e89b-12d3-a456-426614174000:1700000000:nonce:procedure:!!!",
	}
	for _, c := range cases {
		if _, err := ParseChallenge(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestParseAuthPubkey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	if _, err := ParseAuthPubkey(pubPEM); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	if _, err := ParseAuthPubkey([]byte("not a pem")); err == nil {
		t.Fatal("expected error for garbage")
	}
}
