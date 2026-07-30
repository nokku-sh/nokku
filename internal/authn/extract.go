package authn

import (
	"net/http"
	"strings"
)

const (
	AccessTokenCookie  = "nokku.access_token"  // #nosec G101
	RefreshTokenCookie = "nokku.refresh_token" // #nosec G101
	DeviceCookie       = "nokku.device"        // #nosec G101
)

func GetAccessToken(header http.Header) string {
	if token := GetBearerToken(header); token != "" {
		return token
	}
	return GetCookieToken(header, AccessTokenCookie)
}

func GetRefreshToken(header http.Header) string {
	return GetCookieToken(header, RefreshTokenCookie)
}

func GetDeviceToken(header http.Header) string {
	return GetCookieToken(header, DeviceCookie)
}

func GetBearerToken(header http.Header) string {
	const prefix = "Bearer "
	auth := header.Get("Authorization")
	// Case insensitive prefix match. See RFC 9110 Section 11.1.
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return ""
	}
	return auth[len(prefix):]
}

func GetCookieToken(header http.Header, name string) string {
	cookieHeader := header.Get("Cookie")
	if cookieHeader == "" {
		return ""
	}
	cookies, err := http.ParseCookie(cookieHeader)
	if err != nil {
		return ""
	}
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}
