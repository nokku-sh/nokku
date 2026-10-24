package manual

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func probeOutput(passwd ...string) string {
	return sectionPasswd + "\n" + strings.Join(passwd, "\n") + "\n" +
		sectionHostKey + "\nssh-ed25519 AAAAhost root@web\n" +
		sectionPrincipals + "\nalice\ngone\n"
}

func TestParseProbe(t *testing.T) {
	t.Parallel()
	h, err := ParseProbe(probeOutput(
		"root:x:0:0:root:/root:/bin/bash",
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
		"sync:x:5:0:sync:/sbin:/bin/sync",
		"alice:x:1000:1000:Alice:/home/alice:/bin/bash",
		"bob:x:1001:1001:Bob:/home/bob:/usr/bin/false",
		"carol:x:1003:1003:Carol:/home/carol:/bin/zsh",
		"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
		"..:x:1005:1005::/tmp:/bin/sh",
		"we'ird:x:1006:1006::/tmp:/bin/sh",
		"broken:fewer:fields",
		"nauid:x:notanumber:0:x:/home/x:/bin/sh",
	))
	require.NoError(t, err)
	assert.Equal(t, []string{"alice", "carol", "root"}, h.Accounts)
	assert.Equal(t, "ssh-ed25519 AAAAhost root@web", h.HostKey)
	assert.Equal(t, []string{"alice", "gone"}, h.Principals)
}

func TestParseProbeWithoutHostKey(t *testing.T) {
	t.Parallel()
	_, err := ParseProbe(
		sectionPasswd + "\nroot:x:0:0::/root:/bin/sh\n" + sectionHostKey + "\n" + sectionPrincipals + "\n",
	)
	assert.ErrorContains(t, err, "no ssh host key")
}

func TestAccountsPastTheCap(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	out.WriteString(sectionPasswd + "\n")
	for i := range 250 {
		fmt.Fprintf(&out, "user%03d:x:%d:%d::/home/u:/bin/bash\n", i, 1000+i, 1000+i)
	}
	out.WriteString(sectionHostKey + "\nssh-ed25519 AAAA\n" + sectionPrincipals + "\nuser010\nuser240\ngone\n")

	h, err := ParseProbe(out.String())
	require.NoError(t, err)
	assert.Len(t, h.Accounts, maxLocalAccounts)
	assert.Equal(t, "user199", h.Accounts[199])

	p := NewPlan("ca-key", nil, h)
	assert.Equal(t, []string{"/etc/ssh/nokku_principals/gone"}, p.Stale, "an account past the cap keeps its file")
}

func TestNewPlan(t *testing.T) {
	t.Parallel()
	h := Host{Accounts: []string{"alice", "root"}, Principals: []string{"alice", "gone", ".."}}
	p := NewPlan("ca-key\n", map[string][]string{"root": {"id-b", "id-a", "id-b", ""}}, h)

	byPath := map[string]string{}
	for _, f := range p.Files {
		byPath[f.Path] = f.Content
	}
	require.Len(t, byPath, 4, "the CA, the drop-in, and one file per account")
	assert.Equal(t, "ca-key\n", byPath[caPath])
	assert.Equal(
		t,
		"TrustedUserCAKeys /etc/ssh/nokku_ca.pub\nAuthorizedPrincipalsFile /etc/ssh/nokku_principals/%u\n",
		byPath[dropInPath],
	)
	assert.Equal(t, "id-a\nid-b\n", byPath[principalsDir+"/root"])
	assert.Empty(t, byPath[principalsDir+"/alice"], "no grants means an empty deny file")
	assert.Equal(t, []string{principalsDir + "/gone"}, p.Stale)
}

func TestScriptIsValidShell(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	p := NewPlan("ca-key 'quoted'\n", nil, Host{Accounts: []string{"root"}, Principals: []string{"gone"}})
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(p.Script())
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "generated script must parse: %s", out)
}

// runPlan runs the script of p on a fake /etc/ssh holding existing. sshd -t accepts the host as it is, and the
// result only when reject is false.
func runPlan(t *testing.T, p Plan, existing map[string]string, reject bool) (dir, out string, err error) {
	t.Helper()
	if _, lookErr := exec.LookPath("sh"); lookErr != nil {
		t.Skip("sh not available")
	}
	dir = t.TempDir()
	bin := filepath.Join(dir, "bin")
	require.NoError(t, os.Mkdir(bin, 0o755))
	code := 0
	if reject {
		code = 1
	}
	stubs := map[string]string{
		"bin/id":        "#!/bin/sh\necho 0\n",
		"bin/systemctl": "#!/bin/sh\nexit 0\n",
		"bin/sshd": fmt.Sprintf(
			"#!/bin/sh\n[ \"$1\" = -t ] || exit 0\n[ -f %[1]s/checked ] && exit %[2]d\ntouch %[1]s/checked\n",
			dir, code,
		),
	}
	for name, body := range stubs {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755))
	}
	for name, body := range existing {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644))
	}

	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(strings.ReplaceAll(p.Script(), "/etc/ssh", dir))
	cmd.Env = []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH")}
	b, err := cmd.CombinedOutput()
	return dir, string(b), err
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}

func TestScriptWrites(t *testing.T) {
	t.Parallel()
	p := NewPlan("new-ca", map[string][]string{"root": {"p1"}}, Host{Accounts: []string{"root"}})
	dir, out, err := runPlan(t, p, map[string]string{"nokku_ca.pub": "old-ca\n"}, false)
	require.NoError(t, err, out)

	assert.Equal(t, "new-ca\n", readFile(t, filepath.Join(dir, "nokku_ca.pub")))
	assert.Equal(t, "p1\n", readFile(t, filepath.Join(dir, "nokku_principals/root")))
	assert.NoFileExists(t, filepath.Join(dir, "nokku_ca.pub.nokku-bak"))
	assert.True(t, ParseResult(out).Reloaded)
}

func TestScriptRollsBackWhenSSHDRejects(t *testing.T) {
	t.Parallel()
	p := NewPlan("new-ca", nil, Host{Accounts: []string{"root"}})
	dir, out, err := runPlan(t, p, map[string]string{"nokku_ca.pub": "old-ca\n"}, true)
	require.Error(t, err)

	assert.Contains(t, out, "rolled back")
	assert.Equal(t, "old-ca\n", readFile(t, filepath.Join(dir, "nokku_ca.pub")))
	assert.NoFileExists(t, filepath.Join(dir, "sshd_config.d/60-nokku.conf"), "a new file is removed again")
	assert.NoFileExists(t, filepath.Join(dir, "nokku_ca.pub.nokku-bak"))
	assert.False(t, ParseResult(out).Reloaded)
}

// A write that fails halfway, like a full disk, rolls back the files written before it.
func TestScriptRollsBackAFailedWrite(t *testing.T) {
	t.Parallel()
	p := NewPlan("new-ca", nil, Host{Accounts: []string{"root"}})
	dir, out, err := runPlan(t, p, map[string]string{
		"nokku_ca.pub": "old-ca\n",
		// A directory where the staged file goes makes the write fail.
		"nokku_principals/root.nokku-tmp/x": "",
	}, false)
	require.Error(t, err)

	assert.Equal(t, "old-ca\n", readFile(t, filepath.Join(dir, "nokku_ca.pub")))
	assert.NoFileExists(t, filepath.Join(dir, "sshd_config.d/60-nokku.conf"))
	assert.False(t, ParseResult(out).Reloaded)
}

// A backup a dead run left behind must not be restored over the live file.
func TestScriptDropsStaleBackups(t *testing.T) {
	t.Parallel()
	p := NewPlan("new-ca", nil, Host{Accounts: []string{"root"}})
	dir, _, err := runPlan(t, p, map[string]string{
		"nokku_ca.pub":           "live-ca\n",
		"nokku_ca.pub.nokku-bak": "stale-ca\n",
	}, true)
	require.Error(t, err)

	assert.Equal(t, "live-ca\n", readFile(t, filepath.Join(dir, "nokku_ca.pub")))
}

// runRemoveScript runs RemoveScript on a fake /etc/ssh with id, sshd and systemctl stubbed, and returns the dir.
func runRemoveScript(t *testing.T, sshdExit int) (dir, out string, err error) {
	t.Helper()
	if _, lookErr := exec.LookPath("sh"); lookErr != nil {
		t.Skip("sh not available")
	}
	dir = t.TempDir()
	bin := filepath.Join(dir, "bin")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sshd_config.d"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "nokku_principals"), 0o755))
	require.NoError(t, os.Mkdir(bin, 0o755))
	for name, body := range map[string]string{
		"sshd_config.d/60-nokku.conf": "TrustedUserCAKeys x\n",
		"nokku_ca.pub":                "ca\n",
		"nokku_principals/root":       "id\n",
		"bin/id":                      "#!/bin/sh\necho 0\n",
		"bin/sshd":                    fmt.Sprintf("#!/bin/sh\nexit %d\n", sshdExit),
		"bin/systemctl":               "#!/bin/sh\nexit 0\n",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755))
	}

	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(strings.ReplaceAll(RemoveScript, "/etc/ssh", dir))
	cmd.Env = []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH")}
	b, err := cmd.CombinedOutput()
	return dir, string(b), err
}

func TestRemoveScript(t *testing.T) {
	t.Parallel()
	dir, out, err := runRemoveScript(t, 0)
	require.NoError(t, err, out)

	assert.NoFileExists(t, filepath.Join(dir, "sshd_config.d/60-nokku.conf"))
	assert.NoFileExists(t, filepath.Join(dir, "sshd_config.d/60-nokku.conf.nokku-bak"))
	assert.NoFileExists(t, filepath.Join(dir, "nokku_ca.pub"))
	assert.NoDirExists(t, filepath.Join(dir, "nokku_principals"))
	assert.DirExists(t, filepath.Join(dir, "sshd_config.d"), "the drop-in dir belongs to the host")
	assert.True(t, ParseResult(out).Reloaded)
}

func TestRemoveScriptRollsBack(t *testing.T) {
	t.Parallel()
	dir, out, err := runRemoveScript(t, 1)
	require.Error(t, err)

	assert.Contains(t, out, "nothing was removed")
	assert.FileExists(t, filepath.Join(dir, "sshd_config.d/60-nokku.conf"))
	assert.FileExists(t, filepath.Join(dir, "nokku_ca.pub"))
	assert.FileExists(t, filepath.Join(dir, "nokku_principals/root"))
	assert.False(t, ParseResult(out).Reloaded, "a rejected config is never reloaded")
}

func TestParseResult(t *testing.T) {
	t.Parallel()
	out := "written   /etc/ssh/nokku_ca.pub\n" + reloadMarker + "\n"
	assert.Equal(t, Result{Reloaded: true}, ParseResult(out))
	assert.Equal(t, "written   /etc/ssh/nokku_ca.pub\n", Output(out))
}
