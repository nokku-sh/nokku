package api

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDaemonVersion(t *testing.T) {
	tests := []struct {
		name, userAgent, want string
	}{
		{"nokkud", "nokkud/1.4.2 (linux/amd64)", "1.4.2"},
		{"a dev build", "nokkud/(devel) (linux/arm64)", "(devel)"},
		{"no platform", "nokkud/1.4.2", "1.4.2"},
		{"another agent", "connect-go/2.0.0 (go1.27)", ""},
		{"nothing", "", ""},
		{"too long to be a version", "nokkud/" + strings.Repeat("x", 65) + " (linux/amd64)", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, daemonVersion(tt.userAgent))
		})
	}
}
