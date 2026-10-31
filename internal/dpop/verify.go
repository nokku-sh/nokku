package dpop

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	nonceTTL = 5 * time.Minute
	maxSkew  = time.Minute
	// ReplayWindow is how long a replay store has to remember a jti. The iat
	// check takes a proof for two skews at most, the third is slack for a wall
	// clock that steps back.
	ReplayWindow = 3 * maxSkew
)

var (
	// ErrInvalidProof is a proof that does not verify. Every error of
	// [Verifier.Verify] but [ErrNonce] wraps it.
	ErrInvalidProof = errors.New("dpop: invalid proof")
	// ErrNonce asks the client to sign again with the nonce the server sends
	// along (RFC 9449 section 8).
	ErrNonce = errors.New("dpop: nonce required")

	errReplay          = fmt.Errorf("%w: replayed proof", ErrInvalidProof)
	errBindingMismatch = fmt.Errorf("%w: jkt mismatch", ErrInvalidProof)
)

// allowedAlgs is what nk and nokkud sign with, a P-256 key in a TPM or the Secure Enclave.
var allowedAlgs = []jose.SignatureAlgorithm{jose.ES256}

// Verifier checks proofs on the server. Its nonces are a stateless HMAC over
// a time bucket. Only proofs of a session take room in its replay store.
type Verifier struct {
	secret   []byte
	firstUse func(jti [32]byte) bool
	now      func() time.Time
}

// NewVerifier keys the nonces with secret. firstUse records the hash of a
// proof's jti and reports whether it was new, and has to remember it for
// [ReplayWindow]. now is the clock.
func NewVerifier(secret []byte, firstUse func(jti [32]byte) bool, now func() time.Time) *Verifier {
	return &Verifier{secret: secret, firstUse: firstUse, now: now}
}

// ProofFrom returns the request's proof, "" without one. Two DPoP headers are
// refused (RFC 9449 section 4.3).
func ProofFrom(h http.Header) (string, error) {
	proofs := h.Values("DPoP")
	if len(proofs) > 1 {
		return "", fmt.Errorf("%w: more than one DPoP header", ErrInvalidProof)
	}
	if len(proofs) == 0 {
		return "", nil
	}
	return proofs[0], nil
}

// CurrentNonce is the nonce a client should sign with now.
func (v *Verifier) CurrentNonce() string {
	return v.nonceFor(v.bucket(v.now()))
}

func (v *Verifier) bucket(t time.Time) int64 {
	return t.Unix() / int64(nonceTTL.Seconds())
}

func (v *Verifier) nonceFor(bucket int64) string {
	mac := hmac.New(sha256.New, v.secret)
	fmt.Fprintf(mac, "dpop-nonce:%d", bucket)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// nonceValid also accepts the previous bucket so proofs survive a rotation.
func (v *Verifier) nonceValid(nonce string) bool {
	bucket := v.bucket(v.now())
	return subtle.ConstantTimeCompare([]byte(nonce), []byte(v.nonceFor(bucket))) == 1 ||
		subtle.ConstantTimeCompare([]byte(nonce), []byte(v.nonceFor(bucket-1))) == 1
}

// Verify checks proofJWT for a request of htm to htu and returns the proof
// key's thumbprint (jkt). accessToken is the token the request carries, ""
// for none. A non-empty binding is the jkt the token is bound to, it has to
// match before the jti takes room in the replay store.
func (v *Verifier) Verify(proofJWT, accessToken, htm, htu, binding string) (string, error) {
	sig, err := jose.ParseSignedCompact(proofJWT, allowedAlgs)
	if err != nil {
		return "", fmt.Errorf("%w: parse: %w", ErrInvalidProof, err)
	}

	hdr := sig.Signatures[0].Protected
	typ, _ := hdr.ExtraHeaders[jose.HeaderType].(string)
	if !strings.EqualFold(typ, "dpop+jwt") {
		return "", fmt.Errorf("%w: missing dpop+jwt typ", ErrInvalidProof)
	}

	jwk := hdr.JSONWebKey
	if jwk == nil || !jwk.Valid() || !jwk.IsPublic() {
		return "", fmt.Errorf("%w: missing or invalid jwk", ErrInvalidProof)
	}

	payload, err := sig.Verify(jwk.Key)
	if err != nil {
		return "", fmt.Errorf("%w: signature: %w", ErrInvalidProof, err)
	}

	var c struct {
		HTM   string `json:"htm"`
		HTU   string `json:"htu"`
		IAT   int64  `json:"iat"`
		JTI   string `json:"jti"`
		Nonce string `json:"nonce"`
		ATH   string `json:"ath"`
	}
	if err = json.Unmarshal(payload, &c); err != nil {
		return "", fmt.Errorf("%w: claims: %w", ErrInvalidProof, err)
	}
	if c.HTM != htm {
		return "", fmt.Errorf("%w: htm mismatch", ErrInvalidProof)
	}
	if !SameURL(c.HTU, htu) {
		return "", fmt.Errorf("%w: htu mismatch", ErrInvalidProof)
	}
	if c.JTI == "" {
		return "", fmt.Errorf("%w: missing jti", ErrInvalidProof)
	}

	now := v.now().Unix()
	skew := int64(maxSkew.Seconds())
	if diff := now - c.IAT; diff > skew || diff < -skew {
		return "", fmt.Errorf("%w: stale iat", ErrInvalidProof)
	}
	if c.Nonce == "" || !v.nonceValid(c.Nonce) {
		return "", ErrNonce
	}
	if accessToken != "" && subtle.ConstantTimeCompare([]byte(c.ATH), []byte(ATH(accessToken))) != 1 {
		return "", fmt.Errorf("%w: ath mismatch", ErrInvalidProof)
	}

	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("%w: thumbprint: %w", ErrInvalidProof, err)
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
	if !v.firstUse(sha256.Sum256([]byte(c.JTI))) {
		return "", errReplay
	}
	return jkt, nil
}

// SameURL compares two URLs the way an htu is compared: host case, a default
// port, a trailing slash, the query and the fragment do not count. The path
// counts byte for byte.
func SameURL(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil {
		return false
	}
	return ua.Scheme == ub.Scheme &&
		strings.EqualFold(ua.Hostname(), ub.Hostname()) &&
		effectivePort(ua) == effectivePort(ub) &&
		path.Clean("/"+ua.EscapedPath()) == path.Clean("/"+ub.EscapedPath())
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
