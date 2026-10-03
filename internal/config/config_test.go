package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// NOKKU_BASE_URL is the public address. The listen port is not part of it,
// a reverse proxy usually sits in between.
func TestFullURL(t *testing.T) {
	tests := []struct {
		name, baseURL, want string
	}{
		{"unset is the local listener", "", "http://localhost:3000"},
		{"behind a TLS proxy", "https://nokku.example.com", "https://nokku.example.com"},
		{"trailing slash", "https://nokku.example.com/", "https://nokku.example.com"},
		{"explicit port", "http://localhost:5173", "http://localhost:5173"},
		{"plain http behind a proxy", "http://10.0.0.5", "http://10.0.0.5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{BaseURL: tt.baseURL, Port: "3000"}
			assert.Equal(t, tt.want, c.FullURL())
		})
	}
}
