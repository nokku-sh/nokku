package crypto

import (
	"slices"

	"github.com/nokku-sh/nokku/internal/nktoken"
)

// TokenKind says what a token is for. It is the part between "nk_" and the random body, so a token used where it
// does not belong is refused before any lookup, and a secret scanner knows it for one of ours.
type TokenKind string

const (
	TokenSession        TokenKind = "sess"   // a browser session cookie
	TokenCLI            TokenKind = "cli"    // nk's session
	TokenDaemon         TokenKind = "daemon" // nokkud's session
	TokenServiceAccount TokenKind = nktoken.KindServiceAccount
	TokenSCIM           TokenKind = "scim"
	TokenLogin          TokenKind = "login"  // the sign-in link
	TokenEmailChange    TokenKind = "email"  // confirms a new address
	TokenEmailRevert    TokenKind = "revert" // takes the old address back
	TokenInvite         TokenKind = "invite" // the link that creates an invited account
	TokenEnroll         TokenKind = nktoken.KindEnroll
	TokenDeviceCode     TokenKind = "device" // what nk polls with during nk login
)

// NewToken makes "nk_<kind>_<random><checksum>", the one format of every secret the server hands out. Only the hash
// is stored, the plaintext is shown once.
func NewToken(kind TokenKind) (raw string, hash HashedToken) {
	raw = nktoken.New(string(kind))
	return raw, HashToken(raw)
}

// CheckToken tells a token of one of kinds from anything else: a typo, a token of another kind, one of an older
// format. It runs before any lookup. It is a format check, not authentication.
func CheckToken(raw string, kinds ...TokenKind) bool {
	return slices.ContainsFunc(kinds, func(kind TokenKind) bool { return nktoken.Valid(raw, string(kind)) })
}

// TokenHash is [CheckToken] and [HashToken] in one, so no lookup can skip the check. ok is false for a token
// CheckToken refuses.
func TokenHash(raw string, kinds ...TokenKind) (hash HashedToken, ok bool) {
	if !CheckToken(raw, kinds...) {
		return "", false
	}
	return HashToken(raw), true
}
