package ui

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHumanizeDuration(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		want string
	}{
		{"zero", 0, "0ms"},
		{"millis", 900 * time.Millisecond, "900ms"},
		{"seconds", 45 * time.Second, "45s"},
		{"minutes", 3 * time.Minute, "3m"},
		{"minutes and seconds", 3*time.Minute + 12*time.Second, "3m12s"},
		{"hours", 5 * time.Hour, "5h"},
		{"hours and minutes", 5*time.Hour + 30*time.Minute, "5h30m"},
		{"days", 2 * 24 * time.Hour, "2d"},
		{"days and hours", 2*24*time.Hour + 4*time.Hour, "2d4h"},
		{"negative clamps to zero", -5 * time.Minute, "0ms"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, HumanizeDuration(tt.in))
		})
	}
}

func TestPlainDropsEscapeSequences(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "permission denied[2J\nrun nk login", Plain("permission denied\x1b[2J\r\nrun nk login\u009b\x07"))
	assert.Equal(t, "wéb ✔", Plain("wéb ✔"))
}
