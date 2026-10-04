package iam

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/nokku-sh/nokku/internal/cache"
)

var allowedAlgs = []jose.SignatureAlgorithm{
	jose.EdDSA, jose.ES256, jose.ES384, jose.ES512, jose.RS256, jose.PS256,
}

const (
	dpopNonceTTL = 5 * time.Minute
	dpopMaxSkew  = time.Minute
)

// DPoPVerifier nonces are a stateless HMAC over a time bucket, so instances
// share no storage for them. The cache catches jti reuse.
type DPoPVerifier struct {
	secret []byte
	replay *cache.Memory
	now    func() time.Time
}

func (v *DPoPVerifier) CurrentNonce() string {
	return v.nonceFor(v.bucket(v.now()))
}

func (v *DPoPVerifier) bucket(t time.Time) int64 {
	return t.Unix() / int64(dpopNonceTTL.Seconds())
}

func (v *DPoPVerifier) nonceFor(bucket int64) string {
	mac := hmac.New(sha256.New, v.secret)
	fmt.Fprintf(mac, "dpop-nonce:%d", bucket)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// nonceValid also accepts the previous bucket so proofs survive a rotation.
func (v *DPoPVerifier) nonceValid(nonce string) bool {
	bucket := v.bucket(v.now())
	return subtle.ConstantTimeCompare([]byte(nonce), []byte(v.nonceFor(bucket))) == 1 ||
		subtle.ConstantTimeCompare([]byte(nonce), []byte(v.nonceFor(bucket-1))) == 1
}

// Verify returns the proof key's thumbprint (jkt) for the caller to compare.
func (v *DPoPVerifier) Verify(
	ctx context.Context,
	proofJWT, accessToken, htm, htu string,
) (string, error) {
	sig, err := jose.ParseSigned(proofJWT, allowedAlgs)
	if err != nil {
		return "", fmt.Errorf("%w: parse: %w", errInvalidProof, err)
	}
	if len(sig.Signatures) != 1 {
		return "", fmt.Errorf("%w: expected a single signature", errInvalidProof)
	}

	hdr := sig.Signatures[0].Protected
	typ, _ := hdr.ExtraHeaders[jose.HeaderType].(string)
	if !strings.EqualFold(typ, "dpop+jwt") {
		return "", fmt.Errorf("%w: missing dpop+jwt typ", errInvalidProof)
	}

	jwk := hdr.JSONWebKey
	if jwk == nil || !jwk.Valid() || !jwk.IsPublic() {
		return "", fmt.Errorf("%w: missing or invalid jwk", errInvalidProof)
	}

	payload, err := sig.Verify(jwk.Key)
	if err != nil {
		return "", fmt.Errorf("%w: signature: %w", errInvalidProof, err)
	}

	var c dpopClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", fmt.Errorf("%w: claims: %w", errInvalidProof, err)
	}
	if c.HTM != htm {
		return "", fmt.Errorf("%w: htm mismatch", errInvalidProof)
	}
	if !sameHTU(c.HTU, htu) {
		return "", fmt.Errorf("%w: htu mismatch", errInvalidProof)
	}
	if c.JTI == "" {
		return "", fmt.Errorf("%w: missing jti", errInvalidProof)
	}

	now := v.now().Unix()
	skew := int64(dpopMaxSkew.Seconds())
	if diff := now - c.IAT; diff > skew || diff < -skew {
		return "", fmt.Errorf("%w: stale iat", errInvalidProof)
	}
	if c.Nonce == "" || !v.nonceValid(c.Nonce) {
		return "", ErrDPoPNonce
	}
	// Enrollment proofs have no access token yet.
	if accessToken != "" {
		wantATH := DPoPATH(accessToken)
		if subtle.ConstantTimeCompare([]byte(c.ATH), []byte(wantATH)) != 1 {
			return "", fmt.Errorf("%w: ath mismatch", errInvalidProof)
		}
	}

	// Remember the jti as long as its proof could still be accepted.
	added, err := v.replay.SetNX(ctx, "dpop:jti:"+c.JTI, nil, 2*dpopNonceTTL+dpopMaxSkew)
	if err != nil {
		return "", fmt.Errorf("%w: replay store: %w", errInvalidProof, err)
	}
	if !added {
		return "", errReplay
	}

	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("%w: thumbprint: %w", errInvalidProof, err)
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

func (v *DPoPVerifier) verifySession(
	ctx context.Context,
	proofJWT, accessToken, htm, htu, binding string,
) error {
	if binding == "" {
		return fmt.Errorf("%w: session is not DPoP-bound", errInvalidProof)
	}
	jkt, err := v.Verify(ctx, proofJWT, accessToken, htm, htu)
	if err != nil {
		return err
	}
	if jkt != binding {
		return errBindingMismatch
	}
	return nil
}

type dpopClaims struct {
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	JTI   string `json:"jti"`
	Nonce string `json:"nonce"`
	ATH   string `json:"ath"`
}

// DPoPATH is the "ath" claim, base64url(SHA-256(token)).
func DPoPATH(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// sameHTU compares a proof's htu with the URL the request was for. The host is
// case-insensitive and a default port may be left out. Query and fragment do
// not count, the path does, byte for byte.
func sameHTU(claim, want string) bool {
	a, errA := url.Parse(claim)
	b, errB := url.Parse(want)
	if errA != nil || errB != nil {
		return false
	}
	return a.Scheme == b.Scheme &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == effectivePort(b) &&
		path.Clean(a.EscapedPath()) == path.Clean(b.EscapedPath())
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch u.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}
