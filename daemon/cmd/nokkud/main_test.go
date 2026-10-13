package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckAPIURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		url string
		ok  bool
	}{
		{"https://app.nokku.sh", true},
		{"https://10.0.0.5:8443", true},
		{"http://localhost:3000", true},
		{"http://127.0.0.1:3000", true},
		{"http://[::1]:3000", true},
		{"http://nokku.example.com", false},
		{"http://10.0.0.5:3000", false},
		{"http://localhost.example.com", false},
		{"nokku.example.com", false},
		{"ftp://localhost", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.ok, checkAPIURL(tt.url) == nil, "accepted is wrong for %q", tt.url)
		})
	}
}
