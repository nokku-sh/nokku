package ui

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

	"golang.org/x/term"
)

// colorEnabled resolves once at startup, honoring NO_COLOR.
var colorEnabled = func() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return term.IsTerminal(int(os.Stdout.Fd()))
}()

// color wraps s in an SGR code when colors are enabled. The code must exclude
// the leading ESC[ and trailing m.
func color(code, s string) string {
	if !colorEnabled {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func Bold(s string) string   { return color("1", s) }
func Dim(s string) string    { return color("2", s) }
func Red(s string) string    { return color("31", s) }
func Green(s string) string  { return color("32", s) }
func Yellow(s string) string { return color("33", s) }

// Plain drops control characters except newlines from text nk did not write,
// like a server's error message, so it cannot send escape sequences.
func Plain(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' {
			return -1
		}
		return r
	}, s)
}

// HumanizeDuration formats a non-negative duration like "3h12m", "45s", or "900ms".
func HumanizeDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		if s == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm%ds", m, s)
	case d < 24*time.Hour:
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%dm", h, m)
	default:
		days := int(d.Hours() / 24)
		h := int(d.Hours()) % 24
		if h == 0 {
			return fmt.Sprintf("%dd", days)
		}
		return fmt.Sprintf("%dd%dh", days, h)
	}
}
