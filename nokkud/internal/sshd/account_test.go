package sshd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Go calls setgroups(2) whenever Credential is set, and non-root gets EPERM for it.
func TestSysProcAttrNoCredentialWhenNonRoot(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("test must run as a non-root user")
	}

	is := assert.New(t)
	must := require.New(t)

	attr, err := sysProcAttr(&account{Name: "testuser"})
	must.NoError(err)
	is.Nil(attr.Credential)
	is.True(attr.Setsid)

	// End-to-end: the attribute set must actually spawn as this user.
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = attr
	is.NoError(cmd.Run())
}

func TestSysProcAttrCredentialWhenRoot(t *testing.T) {
	t.Parallel()

	if os.Geteuid() != 0 {
		t.Skip("test must run as root")
	}

	is := assert.New(t)
	must := require.New(t)

	attr, err := sysProcAttr(&account{Name: "root"})
	must.NoError(err)
	is.NotNil(attr.Credential)
}

// A fake getent first on PATH exercises the NSS/LDAP paths without a real directory service.
func withFakeGetent(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	must := require.New(t)
	must.NoError(os.WriteFile(filepath.Join(dir, "getent"), []byte(script), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func fakeGetentScript(exitCode int, output string) string {
	if exitCode != 0 {
		return fmt.Sprintf("#!/bin/sh\nexit %d\n", exitCode)
	}
	return fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' '%s'\n", output)
}

func TestLookupAccount(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	withFakeGetent(
		t,
		fakeGetentScript(0, "nokkud-test-alice:x:1001:1002:Alice Test:/home/alice:/bin/bash"),
	)

	a, err := lookupAccount("nokkud-test-alice")
	must.NoError(err)
	is.Equal(account{Name: "nokkud-test-alice", UID: 1001, GID: 1002, Home: "/home/alice", Shell: "/bin/bash"}, *a)
}

func TestLookupAccountShell(t *testing.T) {
	for name, tt := range map[string]struct{ entry, want string }{
		"a lock shell is used as it stands": {"nokkud-test-alice:x:1001:1002::/home/alice:/usr/sbin/nologin", "/usr/sbin/nologin"},
		"an empty shell means /bin/sh":      {"nokkud-test-alice:x:1001:1002::/home/alice:", "/bin/sh"},
	} {
		t.Run(name, func(t *testing.T) {
			withFakeGetent(t, fakeGetentScript(0, tt.entry))
			a, err := lookupAccount("nokkud-test-alice")
			require.NoError(t, err)
			assert.Equal(t, tt.want, a.Shell)
		})
	}
}

func TestLookupAccountRefused(t *testing.T) {
	for name, script := range map[string]string{
		"getent fails":        fakeGetentScript(1, ""),
		"short entry":         fakeGetentScript(0, "nokkud-test-bob:x:1001"),
		"uid is not a number": fakeGetentScript(0, "nokkud-test-bob:x:abc:1002::/home/bob:/bin/sh"),
		// getent resolves a number as a uid and answers with that account.
		"entry for another name": fakeGetentScript(0, "root:x:0:0:root:/root:/bin/bash"),
	} {
		t.Run(name, func(t *testing.T) {
			withFakeGetent(t, script)
			_, err := lookupAccount("nokkud-test-bob")
			assert.Error(t, err)
		})
	}
}

func TestCmdEnv(t *testing.T) {
	is := assert.New(t)
	t.Setenv("LANG", "de_DE.UTF-8")
	t.Setenv("TERM", "screen-256color")
	t.Setenv("TZ", "Europe/Berlin")
	// These must never leak into sessions.
	t.Setenv("DISPLAY", ":0")
	t.Setenv("XAUTHORITY", "/tmp/xauth")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/leak.sock")
	t.Setenv("SSH_CONNECTION", "1.2.3.4 5 6.7.8.9 10")
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")
	t.Setenv("BASH_ENV", "/tmp/evil")

	env := cmdEnv(&account{Name: "alice", Home: "/home/alice", Shell: "/bin/sh"})
	got := map[string]string{}
	must := require.New(t)
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		must.True(ok, "env entry without '=': %q", kv)
		got[k] = v
	}

	for key, want := range map[string]string{
		"HOME":    "/home/alice",
		"USER":    "alice",
		"LOGNAME": "alice",
		"SHELL":   "/bin/sh",
		"LANG":    "de_DE.UTF-8",
		"TZ":      "Europe/Berlin",
	} {
		is.Equal(want, got[key])
	}
	is.NotEmpty(got["PATH"])

	// TERM is the session's to set, the daemon's own never passes.
	for _, leaked := range []string{"TERM", "DISPLAY", "XAUTHORITY", "SSH_AUTH_SOCK", "SSH_CONNECTION", "LD_PRELOAD", "BASH_ENV"} {
		is.NotContains(got, leaked)
	}
}

// The passwd and shadow databases answer from one script, like getent does.
func fakeGetentDatabases(passwd, shadow string) string {
	return fmt.Sprintf(
		"#!/bin/sh\ncase \"$1\" in\npasswd) printf '%%s\\n' '%s' ;;\nshadow) printf '%%s\\n' '%s' ;;\n*) exit 2 ;;\nesac\n",
		passwd,
		shadow,
	)
}

func TestLookupAccountExpiry(t *testing.T) {
	const passwd = "nokkud-test-alice:x:1001:1002::/home/alice:/bin/sh"
	for name, tt := range map[string]struct {
		shadow string
		want   time.Time
	}{
		"expiry day is read":        {"nokkud-test-alice:!:19000:0:99999:7::20000:", time.Unix(20000*24*60*60, 0)},
		"empty field never expires": {"nokkud-test-alice:!:19000:0:99999:7:::", time.Time{}},
		"no shadow entry":           {"", time.Time{}},
		"entry for another name":    {"root:!:19000:0:99999:7::20000:", time.Time{}},
	} {
		t.Run(name, func(t *testing.T) {
			withFakeGetent(t, fakeGetentDatabases(passwd, tt.shadow))
			a, err := lookupAccount("nokkud-test-alice")
			require.NoError(t, err)
			assert.True(t, tt.want.Equal(a.Expires), "expires %s, want %s", a.Expires, tt.want)
		})
	}
}

func TestLoginAllowed(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	path := filepath.Join(t.TempDir(), "nologin")

	nonRoot := &account{Name: "alice", UID: 1000}
	root := &account{Name: "root"}

	is.NoError(loginAllowed(nonRoot, path), "missing file must allow logins")
	is.NoError(loginAllowed(root, path), "missing file must allow root")

	must.NoError(os.WriteFile(path, []byte("maintenance until 17:00\n"), 0o644))
	err := loginAllowed(nonRoot, path)
	must.Error(err, "nologin must deny a non-root login")
	is.Contains(err.Error(), "maintenance until 17:00")

	must.NoError(loginAllowed(root, path), "nologin must never block root")

	absent := filepath.Join(t.TempDir(), "absent")
	expired := &account{Name: "bob", UID: 1001, Expires: time.Now().Add(-time.Hour)}
	err = loginAllowed(expired, absent)
	must.Error(err, "an expired account must be denied")
	is.Contains(err.Error(), "expired")
	must.Error(
		loginAllowed(&account{Name: "root", Expires: time.Now().Add(-time.Hour)}, absent),
		"expiry covers root too",
	)
	must.NoError(loginAllowed(&account{Name: "carol", UID: 1002, Expires: time.Now().Add(time.Hour)}, absent))
}
