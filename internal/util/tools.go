// Package util provides utility functions for the project.
package util

import (
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

func SanitizeUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "")
}

func Uint64ToUnixTime(t uint64) time.Time {
	if t > math.MaxInt64 {
		return time.Unix(math.MaxInt64, 0)
	}
	return time.Unix(int64(t), 0)
}

func UnixTimeToUint64(t int64) uint64 {
	if t < 0 {
		return 0
	}
	return uint64(t)
}
