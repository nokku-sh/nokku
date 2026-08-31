package api

// Remembered-browser-device handling on top of the iam session model: a
// remembered device is a long-lived web_device session issued in its own
// cookie. First login from a device registers it and sends one geo-located
// security alert; later logins from the same device stay quiet.

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
	"github.com/nokku-sh/nokku/internal/util"
)

const (
	deviceCookieName = "nokku_device"
	deviceSessionTTL = 180 * 24 * time.Hour // 6 months, refreshed on each login
)

// rememberDevice reconciles the browser's remembered-device cookie against
// the user's web_device sessions after a successful login. A valid cookie
// refreshes the device session; a missing or unknown cookie registers the
// device and sends one security alert with the IP's geo location.
func (a *authAPI) rememberDevice(w http.ResponseWriter, r *http.Request, u *db.User) {
	if raw := deviceCookie(r); raw != "" {
		if sess, err := a.cfg.IAM.Sessions.Verify(r.Context(), raw); err == nil &&
			sess.Kind == string(iam.KindWebDevice) && sess.SubjectID == u.ID {
			// Known device: the session's idle window just refreshed. No alert.
			return
		}
	}

	name := deviceNameFromUA(r.Header.Get("User-Agent"))
	sess, token, err := a.cfg.IAM.Sessions.Issue(r.Context(), iam.SessionParams{
		SubjectID: u.ID,
		Kind:      iam.KindWebDevice,
		Method:    iam.MethodDevice,
		Label:     name,
		TTL:       deviceSessionTTL,
	})
	if err != nil {
		slog.Error("failed to register device session", "error", err)
		return
	}

	http.SetCookie(w, a.deviceCookie(token, derefTime(sess.ExpiresAt)))

	ip := util.GetRemoteIP(r.Header, r.RemoteAddr)
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
		defer cancel()
		if err := a.cfg.Email.SendNewLoginEmail(
			ctx,
			u.ID,
			u.Email,
			string(sess.TokenHash),
			name,
			a.cfg.Geo.Lookup(ip),
		); err != nil {
			slog.Debug("failed to send new login email", "error", err)
		}
	}()
}

// deviceCookie reads the remembered-device cookie value.
func deviceCookie(r *http.Request) string {
	if c, err := r.Cookie(deviceCookieName); err == nil {
		return c.Value
	}
	return ""
}

// deviceCookie builds the remembered-device cookie: not a login credential,
// just a stable device handle.
func (a *authAPI) deviceCookie(token string, expires time.Time) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // Secure is set dynamically from the base URL scheme
		Name:     deviceCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   a.cfg.IAM.Secure(),
		SameSite: http.SameSiteLaxMode,
	}
}

func deviceNameFromUA(ua string) string {
	if ua == "" {
		return "Unknown device"
	}

	browser := "Unknown browser"
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "OPR/") || strings.Contains(ua, "Opera"):
		browser = "Opera"
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "Chrome/"):
		browser = "Chrome"
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	}

	os := "unknown OS"
	switch {
	case strings.Contains(ua, "Windows"):
		os = "Windows"
	case strings.Contains(ua, "Android"):
		os = "Android"
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad"):
		os = "iOS"
	case strings.Contains(ua, "Mac OS X"):
		os = "macOS"
	case strings.Contains(ua, "CrOS"):
		os = "ChromeOS"
	case strings.Contains(ua, "Linux"):
		os = "Linux"
	}

	return browser + " on " + os
}
