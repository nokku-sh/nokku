package iam

// DPoP (RFC 9449) proof verification, ported from kagi. Device and daemon
// sessions carry the proof key's thumbprint (jkt) in sessions.binding; every
// request must present a fresh proof signed by that key.

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"path"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Errors returned by DPoPVerifier.Verify are sentinels in errors.go. Map
// ErrDPoPNonce to a fresh DPoP-Nonce response header (retry with
// use_dpop_nonce) and everything else to an invalid-proof rejection.

// allowedAlgs is the set of signature algorithms accepted for proofs.
var allowedAlgs = []jose.SignatureAlgorithm{
	jose.EdDSA, jose.ES256, jose.ES384, jose.ES512, jose.RS256, jose.PS256,
}

const (
	// dpopNonceTTL is the rotation period of the server nonce.
	dpopNonceTTL = 5 * time.Minute
	// dpopMaxSkew bounds how far a proof's iat may be from now.
	dpopMaxSkew = time.Minute
)

// DPoPVerifier verifies DPoP proofs. The server nonce is a stateless HMAC
// over a time bucket keyed by the shared secret, so instances validate
// nonces without shared storage. The cache catches jti reuse.
type DPoPVerifier struct {
	secret []byte
	replay Cache
	now    func() time.Time
}

// CurrentNonce returns the nonce to advertise in the DPoP-Nonce header.
func (v *DPoPVerifier) CurrentNonce() string {
	return v.nonceFor(v.bucket(v.now()))
}

// bucket returns the nonce time bucket for t.
func (v *DPoPVerifier) bucket(t time.Time) int64 {
	return t.Unix() / int64(dpopNonceTTL.Seconds())
}

func (v *DPoPVerifier) nonceFor(bucket int64) string {
	mac := hmac.New(sha256.New, v.secret)
	fmt.Fprintf(mac, "dpop-nonce:%d", bucket)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// nonceValid reports whether nonce is the current or previous bucket's nonce,
// so a proof survives a rotation boundary.
func (v *DPoPVerifier) nonceValid(nonce string) bool {
	bucket := v.bucket(v.now())
	return subtle.ConstantTimeCompare([]byte(nonce), []byte(v.nonceFor(bucket))) == 1 ||
		subtle.ConstantTimeCompare([]byte(nonce), []byte(v.nonceFor(bucket-1))) == 1
}

// Verify validates a DPoP proof bound to accessToken and the request
// described by htm/htu, and returns the proof key's thumbprint (jkt). The
// caller compares the jkt against the session's binding.
func (v *DPoPVerifier) Verify(
	ctx context.Context,
	proofJWT, accessToken, htm, htu string,
) (string, error) {
	sig, err := jose.ParseSigned(proofJWT, allowedAlgs)
	if err != nil {
		return "", fmt.Errorf("%w: parse: %w", ErrInvalidProof, err)
	}
	if len(sig.Signatures) != 1 {
		return "", fmt.Errorf("%w: expected a single signature", ErrInvalidProof)
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

	var c dpopClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", fmt.Errorf("%w: claims: %w", ErrInvalidProof, err)
	}
	if c.HTM != htm {
		return "", fmt.Errorf("%w: htm mismatch", ErrInvalidProof)
	}
	// RFC 9449 section 4.2.2: compare normalized htus.
	if !strings.EqualFold(normalizeDPoPHTU(c.HTU), normalizeDPoPHTU(htu)) {
		return "", fmt.Errorf("%w: htu mismatch", ErrInvalidProof)
	}
	if c.JTI == "" {
		return "", fmt.Errorf("%w: missing jti", ErrInvalidProof)
	}

	now := v.now().Unix()
	skew := int64(dpopMaxSkew.Seconds())
	if diff := now - c.IAT; diff > skew || diff < -skew {
		return "", fmt.Errorf("%w: stale iat", ErrInvalidProof)
	}
	if c.Nonce == "" || !v.nonceValid(c.Nonce) {
		return "", ErrDPoPNonce
	}
	// ath is required only alongside an access token. Enrollment proofs have
	// none yet.
	if accessToken != "" {
		wantATH := DPoPATH(accessToken)
		if subtle.ConstantTimeCompare([]byte(c.ATH), []byte(wantATH)) != 1 {
			return "", fmt.Errorf("%w: ath mismatch", ErrInvalidProof)
		}
	}

	// A jti is remembered as long as its proof could still be accepted: two
	// nonce windows plus skew.
	added, err := v.replay.SetNX(ctx, "dpop:jti:"+c.JTI, nil, 2*dpopNonceTTL+dpopMaxSkew)
	if err != nil {
		return "", fmt.Errorf("%w: replay store: %w", ErrInvalidProof, err)
	}
	if !added {
		return "", ErrReplay
	}

	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("%w: thumbprint: %w", ErrInvalidProof, err)
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// VerifySession verifies a proof for a bound session: the proof key's
// thumbprint must match the session's binding.
func (v *DPoPVerifier) VerifySession(
	ctx context.Context,
	proofJWT, accessToken, htm, htu, binding string,
) error {
	if binding == "" {
		return fmt.Errorf("%w: session is not DPoP-bound", ErrInvalidProof)
	}
	jkt, err := v.Verify(ctx, proofJWT, accessToken, htm, htu)
	if err != nil {
		return err
	}
	if jkt != binding {
		return ErrBindingMismatch
	}
	return nil
}

// dpopClaims are the registered claims of a DPoP proof.
type dpopClaims struct {
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	JTI   string `json:"jti"`
	Nonce string `json:"nonce"`
	ATH   string `json:"ath"`
}

// DPoPATH returns the base64url-encoded SHA-256 hash of token, the "ath"
// claim a proof carries alongside the access token.
func DPoPATH(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// normalizeDPoPHTU normalizes a target URI for the RFC 9449 htu comparison
// per RFC 3986 section 6.2.2: drops query and fragment, lowercases scheme
// and host, strips default ports, and normalizes the path.
func normalizeDPoPHTU(htu string) string {
	scheme, rest, ok := strings.Cut(htu, "://")
	if !ok {
		return htu
	}
	rest, _, _ = strings.Cut(rest, "#")
	rest, _, _ = strings.Cut(rest, "?")
	host, p, ok := strings.Cut(rest, "/")
	if ok {
		p = "/" + p
	}
	host = strings.ToLower(host)
	if h, port, err := net.SplitHostPort(host); err == nil {
		if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
			// Keep a bracketed IPv6 host bracketed after stripping the port.
			if strings.Contains(h, ":") {
				host = "[" + h + "]"
			} else {
				host = h
			}
		}
	}
	return strings.ToLower(scheme) + "://" + host + normalizeDPoPPath(p)
}

// normalizeDPoPPath applies RFC 3986 section 6.2.2 path normalization:
// reserved percent-encodings keep their case, dot-segments are removed.
func normalizeDPoPPath(p string) string {
	if p == "" {
		return p
	}
	return path.Clean(normalizePercentEncoding(p))
}

// normalizePercentEncoding decodes percent-encoded unreserved characters and
// uppercases the hex of the encodings it keeps (RFC 3986 section 6.2.2.2), so
// %2F stays distinct from a real "/".
func normalizePercentEncoding(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c == '%' && i+2 < len(s) {
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				octet := hi<<4 | lo
				if isUnreserved(octet) {
					b.WriteByte(octet)
				} else {
					b.WriteByte('%')
					b.WriteByte(upperHex(s[i+1]))
					b.WriteByte(upperHex(s[i+2]))
				}
				i += 3
				continue
			}
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return c == '-' || c == '.' || c == '_' || c == '~'
}

func upperHex(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 'A'
	}
	return c
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
