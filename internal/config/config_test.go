package config

import (
	"testing"

	"github.com/caarlos0/env/v11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/webpki"
)

// NOKKU_BASE_URL names the public host. The listen port is not part of it, a
// reverse proxy usually sits in between. The scheme is never configured.
func TestFullURL(t *testing.T) {
	tests := []struct {
		name, baseURL string
		tls           webpki.Mode
		want          string
	}{
		{"unset is the local listener", "", webpki.ModeOff, "http://localhost:3000"},
		{"a host is reached over https", "nokku.example.com", webpki.ModeOff, "https://nokku.example.com"},
		{"another port", "nokku.example.com:8443", webpki.ModeOff, "https://nokku.example.com:8443"},
		{"localhost stays plain", "localhost:5173", webpki.ModeOff, "http://localhost:5173"},
		{"a name that starts like localhost", "localhost.example.com", webpki.ModeOff, "https://localhost.example.com"},
		{"localhost with a certificate of its own", "", webpki.ModeInternal, "https://localhost:3000"},
		{"a host with a certificate of its own", "nokku.lan:3000", webpki.ModeInternal, "https://nokku.lan:3000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{BaseURL: BaseURL(tt.baseURL), Port: "3000", TLSMode: tt.tls}
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

// A scheme would let someone ask for plain http, and an IP address takes no
// passkey. Both fail the start instead of failing in a browser later.
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

// The check runs where the environment is read, so the server and the
// subcommands all refuse the same values.
func TestBaseURLIsCheckedOnParse(t *testing.T) {
	t.Setenv("NOKKU_BASE_URL", "http://nokku.example.com")
	_, err := env.ParseAs[EnvConfig]()
	require.ErrorContains(t, err, "Leave out the scheme")

	t.Setenv("NOKKU_BASE_URL", "Nokku.Example.com")
	ec, err := env.ParseAs[EnvConfig]()
	require.NoError(t, err)
	assert.Equal(t, "https://nokku.example.com", ec.FullURL())
}

// task backend passes an empty NOKKU_UI_DEV, which has to mean the embedded UI.
func TestDevServerIsOffUnlessNamed(t *testing.T) {
	t.Setenv("NOKKU_BASE_URL", "")
	t.Setenv("NOKKU_UI_DEV", "")
	ec, err := env.ParseAs[EnvConfig]()
	require.NoError(t, err)
	assert.Empty(t, ec.UIDev.Host)

	t.Setenv("NOKKU_UI_DEV", "http://localhost:5173")
	ec, err = env.ParseAs[EnvConfig]()
	require.NoError(t, err)
	assert.Equal(t, "localhost:5173", ec.UIDev.Host)
}

func TestUnsetEnvironmentIsTheLocalListener(t *testing.T) {
	t.Setenv("NOKKU_BASE_URL", "")
	t.Setenv("NOKKU_PORT", "")
	t.Setenv("NOKKU_TLS", "")
	ec, err := env.ParseAs[EnvConfig]()
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:3000", ec.FullURL())

	t.Setenv("NOKKU_TLS", "plain")
	_, err = env.ParseAs[EnvConfig]()
	require.ErrorContains(t, err, "it takes internal")
}
