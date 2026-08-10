package authn

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ChallengeMaxSkew is the maximum allowed age of a signed request challenge.
// The identity signs with its current Unix timestamp; anything older (or from
// the future) than this window is rejected.
const ChallengeMaxSkew = 5 * time.Minute

// Challenge is a signed request challenge of the form
//
//	<identityID>:<unixSeconds>:<nonce>:<procedure>:<base64url(signature)>
//
// The signature covers everything before the final colon, binding the
// challenge to the identity (a daemon or a CLI device), a point in time, a
// fresh nonce and the exact RPC it was created for.
type Challenge struct {
	IdentityID string
	Timestamp  int64
	Nonce      string
	Procedure  string
	Signature  []byte
}

// ParseChallenge parses a raw "Nokku" scheme challenge value.
func ParseChallenge(challenge string) (*Challenge, error) {
	sep := strings.LastIndex(challenge, ":")
	if sep < 0 {
		return nil, errors.New("malformed challenge")
	}
	payload := challenge[:sep]
	sig, err := base64.RawURLEncoding.DecodeString(challenge[sep+1:])
	if err != nil {
		return nil, errors.New("malformed challenge signature")
	}

	parts := strings.Split(payload, ":")
	if len(parts) != 4 {
		return nil, errors.New("malformed challenge payload")
	}
	if _, err := uuid.Parse(parts[0]); err != nil {
		return nil, errors.New("malformed challenge identity id")
	}
	ts, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil, errors.New("malformed challenge timestamp")
	}
	if parts[2] == "" {
		return nil, errors.New("malformed challenge nonce")
	}
	if parts[3] == "" {
		return nil, errors.New("malformed challenge procedure")
	}

	return &Challenge{
		IdentityID: parts[0],
		Timestamp:  ts,
		Nonce:      parts[2],
		Procedure:  parts[3],
		Signature:  sig,
	}, nil
}

// SignedPayload returns the exact bytes the identity signed.
func (c *Challenge) SignedPayload() string {
	return c.IdentityID + ":" + strconv.FormatInt(
		c.Timestamp,
		10,
	) + ":" + c.Nonce + ":" + c.Procedure
}

// Verify checks the challenge signature against a PEM-encoded ECDSA public
// key.
func (c *Challenge) Verify(pubPEM []byte) error {
	pub, err := ParseAuthPubkey(pubPEM)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(c.SignedPayload()))
	if !ecdsa.VerifyASN1(pub, digest[:], c.Signature) {
		return errors.New("invalid challenge signature")
	}
	return nil
}

// ParseAuthPubkey parses and validates a PEM-encoded PKIX ECDSA public key.
func ParseAuthPubkey(pubPEM []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return nil, errors.New("invalid public key encoding")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid public key")
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ECDSA")
	}
	return ecdsaPub, nil
}
