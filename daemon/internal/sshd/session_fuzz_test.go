package sshd

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func FuzzSignalByName(f *testing.F) {
	for name := range sshSignals {
		f.Add(name)
	}
	f.Add("")
	f.Add("SIGTERM")
	f.Add("term")

	f.Fuzz(func(t *testing.T, name string) {
		sig, ok := signalByName(name)
		if !ok {
			return
		}
		require.NotNil(t, sig, "signalByName(%q) returned nil with ok=true", name)
		require.Contains(t, slices.Collect(maps.Values(sshSignals)), sig,
			"signalByName(%q) maps to no RFC 4254 name", name)
	})
}

func FuzzExitCodeToU32(f *testing.F) {
	f.Add(0)
	f.Add(1)
	f.Add(255)
	f.Add(256)
	f.Add(-1)
	f.Add(128)

	f.Fuzz(func(t *testing.T, code int) {
		got := exitCodeToU32(code)
		require.LessOrEqual(t, got, uint32(255), "exitCodeToU32(%d)", code)
		if code >= 0 && code <= 255 {
			require.Equal(t, uint32(code), got, "exitCodeToU32(%d)", code)
			return
		}
		require.Equal(t, uint32(1), got, "exitCodeToU32(%d)", code)
	})
}

func FuzzAllowedEnv(f *testing.F) {
	f.Add("TERM")
	f.Add("LC_ALL")
	f.Add("LC_MESSAGES")
	f.Add("LD_PRELOAD")
	f.Add("PATH")
	f.Add("")

	f.Fuzz(func(t *testing.T, name string) {
		if !allowedEnv(name) {
			return
		}
		switch name {
		case "TERM", "LANG", "TZ", "TERM_PROGRAM", "COLORTERM":
		default:
			require.True(t, strings.HasPrefix(name, "LC_"), "allowedEnv(%q) = true, but it is not whitelisted", name)
		}
	})
}

func FuzzSetEnv(f *testing.F) {
	f.Add("TERM", "xterm")
	f.Add("LC_MESSAGES", "de_DE.UTF-8")
	f.Add("FOO=bar", "value")

	f.Fuzz(func(t *testing.T, key, value string) {
		sess := &session{}
		sess.setEnv(key, value)
		sess.setEnv(key, value+"2")

		kv := key + "="
		count := 0
		for _, e := range sess.env {
			if !strings.HasPrefix(e, kv) {
				continue
			}
			count++
			require.Equal(t, kv+value+"2", e, "setEnv(%q) left a stale entry", key)
		}
		require.Equal(t, 1, count, "setEnv(%q) entries", key)
	})
}
