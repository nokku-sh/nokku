package authn

import "time"

// Token type constants.
const (
	AccessToken  = "access"
	RefreshToken = "refresh"
	VerifyToken  = "verification"
	CLIToken     = "cli"
)

// Default token expirations.
var defaultExpiry = map[string]time.Duration{
	AccessToken:  15 * time.Minute,
	RefreshToken: 7 * 24 * time.Hour,
	VerifyToken:  15 * time.Minute,
	CLIToken:     10 * time.Minute,
}

// GetTokenTTL returns the configured expiry duration for a token type.
func GetTokenTTL(tokenType string) time.Duration {
	return defaultExpiry[tokenType]
}
