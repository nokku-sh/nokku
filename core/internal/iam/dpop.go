package iam

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/nokku-sh/nokku/core/internal/cache"
)

// allowedAlgs is what nk and nokkud sign with, a P-256 key in a TPM or the Secure Enclave.
var allowedAlgs = []jose.SignatureAlgorithm{jose.ES256}

const (
	dpopNonceTTL = 5 * time.Minute
	dpopMaxSkew  = time.Minute
	// A marker lives three minutes, so this is room for about 550 proofs a second.
	dpopReplayEntries = 100_000
)

// DPoPVerifier nonces are a stateless HMAC over a time bucket. Only proofs of a session fill its replay cache.
type DPoPVerifier struct {
	secret []byte
	replay *cache.TTL[[32]byte, struct{}]
	now    func() time.Time
}

// DPoPProof is the request's proof, "" without one. Two DPoP headers are refused (RFC 9449 section 4.3).
func DPoPProof(h http.Header) (string, error) {
	proofs := h.Values("DPoP")
	if len(proofs) > 1 {
		return "", fmt.Errorf("%w: more than one DPoP header", errInvalidProof)
	}
	if len(proofs) == 0 {
		return "", nil
	}
	return proofs[0], nil
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

// Verify returns the proof key's thumbprint (jkt). A binding has to match it before the jti takes room in the store.
func (v *DPoPVerifier) Verify(proofJWT, accessToken, htm, htu, binding string) (string, error) {
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
	if accessToken != "" {
		wantATH := DPoPATH(accessToken)
		if subtle.ConstantTimeCompare([]byte(c.ATH), []byte(wantATH)) != 1 {
			return "", fmt.Errorf("%w: ath mismatch", errInvalidProof)
		}
	}

	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("%w: thumbprint: %w", errInvalidProof, err)
	}
	jkt := base64.RawURLEncoding.EncodeToString(tp)
	if binding != "" && jkt != binding {
		return "", errBindingMismatch
	}
	// A proof without a session is for enrollment or the device poll, and each spends something single-use. Anyone
	// can sign one, so it gets no room in the store.
	if accessToken == "" {
		return jkt, nil
	}

	// Hashed so a long jti cannot bloat the store.
	if !v.replay.SetNX(sha256.Sum256([]byte(c.JTI)), struct{}{}) {
		return "", errReplay
	}
	return jkt, nil
}

func (v *DPoPVerifier) verifySession(proofJWT, accessToken, htm, htu, binding string) error {
	if binding == "" {
		return fmt.Errorf("%w: session is not DPoP-bound", errInvalidProof)
	}
	_, err := v.Verify(proofJWT, accessToken, htm, htu, binding)
	return err
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

// sameHTU ignores host case, a default port, query and fragment. The path counts byte for byte.
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
