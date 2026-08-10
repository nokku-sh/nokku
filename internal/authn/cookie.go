package authn

import (
	"context"
	"net/http"
	"time"

	"github.com/nokku-sh/nokku/internal/db"
)

// deviceCookieMaxAge is how long a browser is remembered as a known device.
// Independent of the session cookies, the server-side row expires after
// 6 months of inactivity (sliding).
const deviceCookieMaxAge = 365 * 24 * time.Hour

func (s *Service) AccessCookie(_ context.Context, res http.Header, user *db.User) string {
	accessToken, err := s.CreateToken(&TokenParams{
		UserID:    user.ID,
		Email:     user.Email,
		Username:  user.Username,
		TokenType: AccessToken,
	})
	if err != nil {
		return ""
	}
	setCookie(res, AccessTokenCookie, accessToken, defaultExpiry[AccessToken])
	return accessToken
}

func (s *Service) RefreshCookie(_ context.Context, res http.Header, user *db.User) string {
	refreshToken, err := s.CreateToken(&TokenParams{
		UserID:    user.ID,
		Email:     user.Email,
		Username:  user.Username,
		TokenType: RefreshToken,
	})
	if err != nil {
		return ""
	}
	setCookie(res, RefreshTokenCookie, refreshToken, defaultExpiry[RefreshToken])
	return refreshToken
}

// SetRefreshCookie writes an existing refresh token to the refresh cookie.
// Used when rotating the token on refresh.
func SetRefreshCookie(res http.Header, token string) {
	setCookie(res, RefreshTokenCookie, token, defaultExpiry[RefreshToken])
}

// SetDeviceCookie marks the browser as a known device for security alerts.
// The token grants no access.
func SetDeviceCookie(res http.Header, token string) {
	// #nosec G124 -- SameSite=None is intentional: the cookie is
	// HttpOnly+Secure, authorizes nothing, and must survive the SAML ACS
	// cross-site POST to mark the browser as a known device.
	cookie := http.Cookie{
		Name:     DeviceCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   int(deviceCookieMaxAge.Seconds()),
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}
	res.Add("Set-Cookie", cookie.String())
}

func ClearCookies(res http.Header) {
	setCookie(res, AccessTokenCookie, "", -1*time.Second)
	setCookie(res, RefreshTokenCookie, "", -1*time.Second)
}

// setCookie adds a cookie with standard security attributes.
func setCookie(res http.Header, name, value string, duration time.Duration) {
	cookie := http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   int(duration.Seconds()),
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	res.Add("Set-Cookie", cookie.String())
}
