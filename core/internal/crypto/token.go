package crypto

import (
	"slices"

	"github.com/nokku-sh/nokku/internal/nktoken"
)

const (
	TokenSession        TokenKind = "sess" // a browser cookie
	TokenCLI            TokenKind = "cli"
	TokenDaemon         TokenKind = "daemon"
	TokenServiceAccount TokenKind = nktoken.KindServiceAccount
	TokenSCIM           TokenKind = "scim"
	TokenLogin          TokenKind = "login"  // the sign-in link
	TokenEmailChange    TokenKind = "email"  // confirms a new address
	TokenEmailRevert    TokenKind = "revert" // takes the old address back
	TokenInvite         TokenKind = "invite"
	TokenEnroll         TokenKind = nktoken.KindEnroll
	TokenDeviceCode     TokenKind = "device" // nk login polls with it
)

// TokenKind is the part between "nk_" and the random body. A token used where
// it does not belong is refused before any lookup, and secret scanners know it.
type TokenKind string

// NewToken makes "nk_<kind>_<random><checksum>". Only the hash is stored, the
// plaintext is shown once.
func NewToken(kind TokenKind) (raw string, hash HashedToken) {
	raw = nktoken.New(string(kind))
	return raw, HashToken(raw)
}

// checkToken runs before any lookup. It is a format check, not authentication.
func checkToken(raw string, kinds ...TokenKind) bool {
	return slices.ContainsFunc(kinds, func(kind TokenKind) bool { return nktoken.Valid(raw, string(kind)) })
}

// TokenHash is [checkToken] plus [HashToken], so no lookup skips the check.
func TokenHash(raw string, kinds ...TokenKind) (hash HashedToken, ok bool) {
	if !checkToken(raw, kinds...) {
		return "", false
	}
	return HashToken(raw), true
}
