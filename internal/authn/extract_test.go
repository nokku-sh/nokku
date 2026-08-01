package authn

import (
	"net/http"
	"testing"
)

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"standard bearer", "Bearer abc123", "abc123"},
		{"lowercase scheme", "bearer abc123", "abc123"},
		{"mixed case scheme", "BeArEr abc123", "abc123"},
		{"empty header", "", ""},
		{"wrong scheme", "Basic abc123", ""},
		{"missing space", "Bearerabc123", ""},
		{"only scheme", "Bearer", ""},
		{"leading whitespace", "  Bearer abc123", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			if tt.header != "" {
				h.Set("Authorization", tt.header)
			}
			if got := GetBearerToken(h); got != tt.want {
				t.Errorf("GetBearerToken() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetCookieToken(t *testing.T) {
	tests := []struct {
		name   string
		cookie string
		want   string
	}{
		{"single cookie", "nokku.access_token=abc", "abc"},
		{
			"multiple cookies picks the right one",
			"session=x; nokku.access_token=abc; other=y",
			"abc",
		},
		{"no matching cookie", "session=x", ""},
		{"empty cookie header", "", ""},
		{"malformed cookie header", ";;;===", ""},
		{"value with equals sign", "nokku.access_token=a=b=c", "a=b=c"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			if tt.cookie != "" {
				h.Set("Cookie", tt.cookie)
			}
			if got := GetCookieToken(h, AccessTokenCookie); got != tt.want {
				t.Errorf("GetCookieToken(%q) = %q, want %q", tt.cookie, got, tt.want)
			}
		})
	}
}

func TestGetAccessToken_BearerTakesPriority(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer from-header")
	h.Set("Cookie", "nokku.access_token=from-cookie")

	if got := GetAccessToken(h); got != "from-header" {
		t.Errorf("GetAccessToken() = %q, want bearer value", got)
	}

	if got := GetRefreshToken(h); got != "" {
		t.Errorf("GetRefreshToken() = %q, want empty (no refresh cookie)", got)
	}
}

func TestGetAccessToken_CookieFallback(t *testing.T) {
	h := http.Header{}
	h.Set("Cookie", "nokku.access_token=from-cookie; nokku.refresh_token=ref; nokku.device=dev")

	if got := GetAccessToken(h); got != "from-cookie" {
		t.Errorf("GetAccessToken() = %q, want from-cookie", got)
	}
	if got := GetRefreshToken(h); got != "ref" {
		t.Errorf("GetRefreshToken() = %q, want ref", got)
	}
	if got := GetDeviceToken(h); got != "dev" {
		t.Errorf("GetDeviceToken() = %q, want dev", got)
	}
}

func TestGetAccessToken_None(t *testing.T) {
	if got := GetAccessToken(http.Header{}); got != "" {
		t.Errorf("GetAccessToken() = %q, want empty", got)
	}
}
