package sshd

import (
	"strings"
	"testing"
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
		if sig == nil {
			t.Fatalf("signalByName(%q) returned nil with ok=true", name)
		}
		mapped := false
		for _, s := range sshSignals {
			if s == sig {
				mapped = true
				break
			}
		}
		if !mapped {
			t.Fatalf("signalByName(%q) = %v, which maps to no RFC 4254 name", name, sig)
		}
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
		if got > 255 {
			t.Fatalf("exitCodeToU32(%d) = %d, exceeds 255", code, got)
		}
		if code >= 0 && code <= 255 {
			if got != uint32(code) {
				t.Fatalf("exitCodeToU32(%d) = %d, want %d", code, got, code)
			}
			return
		}
		if got != 1 {
			t.Fatalf("exitCodeToU32(%d) = %d, want 1", code, got)
		}
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
			if !strings.HasPrefix(name, "LC_") {
				t.Fatalf("allowedEnv(%q) = true, but %q is not whitelisted", name, name)
			}
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
			if e != kv+value+"2" {
				t.Fatalf("setEnv(%q) left stale entry %q", key, e)
			}
		}
		if count != 1 {
			t.Fatalf("setEnv(%q) produced %d entries, want 1", key, count)
		}
	})
}
