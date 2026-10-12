package config

import (
	"net"
	"net/http"
	"testing"

	"github.com/caarlos0/env/v11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/realip"
)

// NOKKU_BASE_URL names the public host. The listen port is not part of it, the scheme is never configured.
func TestFullURL(t *testing.T) {
	tests := []struct {
		name, baseURL, want string
	}{
		{"unset is the local listener", "", "http://localhost:3000"},
		{"a host is reached over https", "nokku.example.com", "https://nokku.example.com"},
		{"another port", "nokku.example.com:8443", "https://nokku.example.com:8443"},
		{"localhost stays plain", "localhost:5173", "http://localhost:5173"},
		{"a name that starts like localhost", "localhost.example.com", "https://localhost.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{BaseURL: BaseURL(tt.baseURL), Port: "3000"}
			assert.Equal(t, tt.want, c.FullURL())
		})
	}
}

func TestHostnameHasNoPort(t *testing.T) {
	assert.Equal(t, "nokku.lan", (&EnvConfig{BaseURL: "nokku.lan:3000"}).Hostname())
	assert.Equal(t, "localhost", (&EnvConfig{Port: "3000"}).Hostname())
}

func TestBaseURLAccepts(t *testing.T) {
	for in, want := range map[string]string{
		"nokku.example.com":       "nokku.example.com",
		"Nokku.Example.COM":       "nokku.example.com",
		"nokku.internal:8443":     "nokku.internal:8443",
		"localhost:3000":          "localhost:3000",
		"10-0-0-5.sslip.io":       "10-0-0-5.sslip.io",
		"nokku":                   "nokku",
		"xn--nkku-5qa.example.de": "xn--nkku-5qa.example.de",
	} {
		var b BaseURL
		require.NoError(t, b.UnmarshalText([]byte(in)), in)
		assert.Equal(t, BaseURL(want), b)
	}
}

// A scheme and an IP address both fail the start instead of failing in a browser later.
func TestBaseURLRefuses(t *testing.T) {
	for in, want := range map[string]string{
		"https://nokku.example.com": "Leave out the scheme",
		"http://10.0.0.5:3000":      "Leave out the scheme",
		"nokku.example.com/app":     "Leave out the scheme",
		"http://localhost:5173":     "Leave out the scheme",
		"10.0.0.5":                  "IP address 10.0.0.5",
		"10.0.0.5:3000":             "IP address 10.0.0.5",
		"127.0.0.1:3000":            "IP address 127.0.0.1",
		"[::1]:3000":                "IP address ::1",
		"::1":                       "optional port",
		"nokku.example.com:https":   "optional port",
	} {
		var b BaseURL
		require.ErrorContains(t, b.UnmarshalText([]byte(in)), want, in)
		assert.Empty(t, b, in)
	}
}

// The check runs where the environment is read, so the server and the subcommands refuse the same values.
func TestBaseURLIsCheckedOnParse(t *testing.T) {
	t.Setenv("NOKKU_BASE_URL", "http://nokku.example.com")
	_, err := env.ParseAs[EnvConfig]()
	require.ErrorContains(t, err, "Leave out the scheme")

	t.Setenv("NOKKU_BASE_URL", "Nokku.Example.com")
	ec, err := env.ParseAs[EnvConfig]()
	require.NoError(t, err)
	assert.Equal(t, "https://nokku.example.com", ec.FullURL())
}

func TestUnsetEnvironmentIsTheLocalListener(t *testing.T) {
	t.Setenv("NOKKU_BASE_URL", "")
	t.Setenv("NOKKU_PORT", "")
	ec, err := env.ParseAs[EnvConfig]()
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:3000", ec.FullURL())
}

// A proxy in a container network or on this machine works with nothing set. A public address never does.
func TestProxiesTrustedByDefault(t *testing.T) {
	t.Setenv("NOKKU_TRUSTED_PROXIES", "")
	ec, err := env.ParseAs[EnvConfig]()
	require.NoError(t, err)
	require.NoError(t, realip.SetTrustedProxies(ec.TrustedProxies))
	t.Cleanup(func() { _ = realip.SetTrustedProxies(nil) })

	forwarded := http.Header{"X-Forwarded-Proto": {"https"}}
	for _, peer := range []string{"127.0.0.1", "::1", "10.42.0.7", "172.28.0.3", "192.168.1.20", "fd00::3"} {
		assert.Equal(t, "https", realip.Proto(forwarded, net.JoinHostPort(peer, "4242")), peer)
	}
	for _, peer := range []string{"203.0.113.7", "172.32.0.1", "2001:db8::1"} {
		assert.Empty(t, realip.Proto(forwarded, net.JoinHostPort(peer, "4242")), peer)
	}

	t.Setenv("NOKKU_TRUSTED_PROXIES", "203.0.113.7")
	ec, err = env.ParseAs[EnvConfig]()
	require.NoError(t, err)
	assert.Equal(t, []string{"203.0.113.7"}, ec.TrustedProxies, "a list of your own replaces the default")
}
