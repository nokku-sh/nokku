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
	"net"
	"path"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
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
	replay Cache
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
	// Enrollment proofs have no access token yet.
	if accessToken != "" {
		wantATH := DPoPATH(accessToken)
		if subtle.ConstantTimeCompare([]byte(c.ATH), []byte(wantATH)) != 1 {
			return "", fmt.Errorf("%w: ath mismatch", ErrInvalidProof)
		}
	}

	// Remember the jti as long as its proof could still be accepted.
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

// normalizeDPoPHTU follows RFC 3986 section 6.2.2.
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
			if strings.Contains(h, ":") {
				host = "[" + h + "]"
			} else {
				host = h
			}
		}
	}
	return strings.ToLower(scheme) + "://" + host + normalizeDPoPPath(p)
}

func normalizeDPoPPath(p string) string {
	if p == "" {
		return p
	}
	return path.Clean(normalizePercentEncoding(p))
}

// normalizePercentEncoding only decodes unreserved characters, so %2F stays
// distinct from a real "/".
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
