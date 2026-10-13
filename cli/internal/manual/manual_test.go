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

func TestLocalAccountsCap(t *testing.T) {
	t.Parallel()
	var lines []string
	for i := range 250 {
		lines = append(lines, fmt.Sprintf("user%03d:x:%d:%d::/home/u:/bin/bash", i, 1000+i, 1000+i))
	}
	accounts := localAccounts(lines)
	assert.Len(t, accounts, maxLocalAccounts)
	assert.Equal(t, "user199", accounts[199])
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

// runRemoveScript runs RemoveScript against a fake /etc/ssh, with id, sshd,
// and systemctl stubbed on PATH. It returns the fake dir.
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
