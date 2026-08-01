package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/nokku-sh/nokku/internal/authn"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/util"
)

const (
	deviceKindCLI = "cli"
	deviceKindWeb = "web"
)

// syncWebDevice reconciles the browser's remembered-device cookie against the
// user's known devices after a successful web login. A matching cookie just
// marks the device as used; a missing or unknown cookie registers a new
// device, refreshes the cookie, and sends one security alert.
func syncWebDevice(
	ctx context.Context,
	cfg *config.Config,
	reqHeader, resHeader http.Header,
	peerAddr string,
	user *db.User,
) {
	if raw := authn.GetDeviceToken(reqHeader); raw != "" {
		if parsed, err := crypto.Parse(raw); err == nil && parsed.ID != "" {
			device, err := cfg.Conn.Q.GetUserWebDevice(ctx, &db.GetUserWebDeviceParams{
				ID:     parsed.ID,
				UserID: user.ID,
			})
			if err == nil && device.TokenHash.Verify(raw) {
				// Known device: refresh usage (throttled), no alert.
				_ = cfg.Conn.Q.UpdateUserDeviceUsage(ctx, parsed.ID)
				return
			}
		}
	}

	token, err := crypto.NewDeviceToken()
	if err != nil {
		slog.Error("failed to create device token", "error", err)
		return
	}
	name := deviceNameFromUA(reqHeader.Get("User-Agent"))

	if err := cfg.Conn.Q.CreateUserDevice(ctx, &db.CreateUserDeviceParams{
		ID:        token.ID,
		UserID:    user.ID,
		Name:      name,
		Kind:      deviceKindWeb,
		TokenHash: token.Hash,
	}); err != nil {
		slog.Error("failed to register device", "error", err)
		return
	}

	authn.SetDeviceCookie(resHeader, token.Plaintext)
	ipStr := util.GetRemoteIP(reqHeader, peerAddr)

	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := cfg.Email.SendNewLoginEmail(
			ctx,
			user.ID,
			user.Email,
			token.ID,
			name,
			cfg.Geo.Lookup(ipStr),
		); err != nil {
			slog.Debug("failed to send device added email", "error", err)
		}
	}()
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
