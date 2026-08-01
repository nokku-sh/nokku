package util

import (
	"math"
	"testing"
	"time"
)

func TestUint64ToUnixTime(t *testing.T) {
	tests := []struct {
		name string
		in   uint64
		want time.Time
	}{
		{"zero", 0, time.Unix(0, 0)},
		{"regular value", 1_700_000_000, time.Unix(1_700_000_000, 0)},
		{"max int64", math.MaxInt64, time.Unix(math.MaxInt64, 0)},
		{"overflow clamps to max int64", math.MaxInt64 + 1, time.Unix(math.MaxInt64, 0)},
		{"max uint64 clamps", math.MaxUint64, time.Unix(math.MaxInt64, 0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Uint64ToUnixTime(tt.in); !got.Equal(tt.want) {
				t.Errorf("Uint64ToUnixTime(%d) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestUnixTimeToUint64(t *testing.T) {
	tests := []struct {
		name string
		in   int64
		want uint64
	}{
		{"zero", 0, 0},
		{"positive", 1_700_000_000, 1_700_000_000},
		{"negative clamps to zero", -1, 0},
		{"min int64 clamps", math.MinInt64, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UnixTimeToUint64(tt.in); got != tt.want {
				t.Errorf("UnixTimeToUint64(%d) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestSanitizeUTF8(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"valid string unchanged", "héllo wörld", "héllo wörld"},
		{"empty unchanged", "", ""},
		{"invalid bytes dropped", "a\xffb\xc3\x28c", "ab(c"},
		{"truncated multibyte dropped", "ok\xe2\x82", "ok"},
		{"ascii unchanged", "plain ascii", "plain ascii"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizeUTF8(tt.in); got != tt.want {
				t.Errorf("SanitizeUTF8(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
