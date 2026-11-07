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

const testTargetID = "0199a0a0-0000-7000-8000-000000000002"

func TestParseProbe(t *testing.T) {
	t.Parallel()
	h, err := ParseProbe(sectionPasswd + "\n" +
		"root:x:0:0:root:/root:/bin/bash\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"alice:x:1000:1000:Alice:/home/alice:/bin/bash\n" +
		sectionHostKey + "\nssh-ed25519 AAAAhost root@web\n")
	require.NoError(t, err)
	assert.Equal(t, []string{"alice", "root"}, h.Accounts)
	assert.Equal(t, "ssh-ed25519 AAAAhost root@web", h.HostKey)
}

func TestParseProbeWithoutHostKey(t *testing.T) {
	t.Parallel()
	_, err := ParseProbe(sectionPasswd + "\nroot:x:0:0::/root:/bin/sh\n" + sectionHostKey + "\n")
	assert.ErrorContains(t, err, "no ssh host key")
}

// The probe runs on a fake /etc, so its sections must be the ones ParseProbe reads.
func TestProbeCommand(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	require.NoError(t, os.Mkdir(filepath.Join(dir, "ssh"), 0o755))
	require.NoError(t, os.Mkdir(bin, 0o755))
	for name, body := range map[string]string{
		"bin/id":                     "#!/bin/sh\necho 0\n",
		"bin/getent":                 "#!/bin/sh\nexit 2\n",
		"passwd":                     "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n",
		"ssh/ssh_host_ecdsa_key.pub": "ecdsa-sha2-nistp256 AAAAecdsa root@web\n",
		"ssh/ssh_host_rsa_key.pub":   "ssh-rsa AAAArsa root@web\n",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755))
	}

	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(strings.ReplaceAll(ProbeCommand, "/etc", dir))
	cmd.Env = []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH")}
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)

	h, err := ParseProbe(string(out))
	require.NoError(t, err)
	assert.Equal(t, []string{"alice", "root"}, h.Accounts, "read from /etc/passwd when getent fails")
	assert.Equal(t, "ecdsa-sha2-nistp256 AAAAecdsa root@web", h.HostKey, "without ed25519 the probe takes ecdsa")
}

func TestNewPlan(t *testing.T) {
	t.Parallel()
	p, err := NewPlan("ca-key\n", testTargetID)
	require.NoError(t, err)

	require.Len(t, p.Files, 2, "the CA and the drop-in")
	assert.Equal(t, File{Path: caPath, Content: "ca-key\n"}, p.Files[0])
	assert.Equal(t, File{Path: dropInPath, Content: "TrustedUserCAKeys /etc/ssh/nokku_ca.pub\n" +
		"AuthorizedPrincipalsCommand /bin/echo " + testTargetID + ":%u\n" +
		"AuthorizedPrincipalsCommandUser nobody\n"}, p.Files[1])
}

// A dry run of a new server shows where its id will go.
func TestNewPlanBeforeTheTargetExists(t *testing.T) {
	t.Parallel()
	p, err := NewPlan("ca-key", "")
	require.NoError(t, err)
	assert.Contains(t, p.Files[1].Content, "AuthorizedPrincipalsCommand /bin/echo <target-id>:%u\n")
}

// The id lands in sshd_config, so anything but a UUID could add a directive.
func TestNewPlanRefusesAnUnusableID(t *testing.T) {
	t.Parallel()
	for _, id := range []string{
		testTargetID + "\nPermitRootLogin yes",
		"not-a-uuid",
		strings.ToUpper(testTargetID),
		"{" + testTargetID + "}",
		"urn:uuid:" + testTargetID,
	} {
		_, err := NewPlan("ca-key", id)
		assert.ErrorContains(t, err, "unusable target id", "%q", id)
	}
}

func TestScriptIsValidShell(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	p, err := NewPlan("ca-key 'quoted'\n", testTargetID)
	require.NoError(t, err)
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(p.Script())
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "generated script must parse: %s", out)
}

// runPlan runs p's script on a fake /etc/ssh holding existing. sshd -t takes
// the host as it is, and the result unless reject is set. The reload works only
// with reload set.
func runPlan(t *testing.T, p Plan, existing map[string]string, reject, reload bool) (dir, out string, err error) {
	t.Helper()
	if _, lookErr := exec.LookPath("sh"); lookErr != nil {
		t.Skip("sh not available")
	}
	dir = t.TempDir()
	bin := filepath.Join(dir, "bin")
	require.NoError(t, os.Mkdir(bin, 0o755))
	code, reloadCode := 0, 1
	if reject {
		code = 1
	}
	if reload {
		reloadCode = 0
	}
	stubs := map[string]string{
		"bin/id":        "#!/bin/sh\necho 0\n",
		"bin/systemctl": fmt.Sprintf("#!/bin/sh\nexit %d\n", reloadCode),
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

	// The pid files of the host's own sshd stay out of reach.
	script := strings.NewReplacer("/etc/ssh", dir, "/run/sshd.pid", dir+"/sshd.pid").Replace(p.Script())
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(script)
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

func testPlan(t *testing.T) Plan {
	t.Helper()
	p, err := NewPlan("new-ca", testTargetID)
	require.NoError(t, err)
	return p
}

func TestScriptWrites(t *testing.T) {
	t.Parallel()
	p := testPlan(t)
	dir, out, err := runPlan(t, p, map[string]string{"nokku_ca.pub": "old-ca\n"}, false, true)
	require.NoError(t, err, out)

	assert.Equal(t, "new-ca\n", readFile(t, filepath.Join(dir, "nokku_ca.pub")))
	assert.Equal(t, strings.ReplaceAll(p.Files[1].Content, "/etc/ssh", dir),
		readFile(t, filepath.Join(dir, "sshd_config.d/60-nokku.conf")))
	assert.NoFileExists(t, filepath.Join(dir, "nokku_ca.pub.nokku-bak"))
	assert.True(t, ParseResult(out).Reloaded)
}

// A server set up with a file per account gets the drop-in, and the files go.
func TestScriptReplacesTheOldSetup(t *testing.T) {
	t.Parallel()
	p := testPlan(t)
	dir, out, err := runPlan(t, p, map[string]string{
		"nokku_ca.pub": "new-ca\n",
		"sshd_config.d/60-nokku.conf": "TrustedUserCAKeys /etc/ssh/nokku_ca.pub\n" +
			"AuthorizedPrincipalsFile /etc/ssh/nokku_principals/%u\n",
		"nokku_principals/root":  "0199a0a0-0000-7000-8000-000000000001@" + testTargetID + ":root\n",
		"nokku_principals/alice": "",
	}, false, true)
	require.NoError(t, err, out)

	assert.Equal(t, strings.ReplaceAll(p.Files[1].Content, "/etc/ssh", dir),
		readFile(t, filepath.Join(dir, "sshd_config.d/60-nokku.conf")))
	assert.NoDirExists(t, filepath.Join(dir, "nokku_principals"))
	assert.Contains(t, out, "removed   "+dir+"/nokku_principals")
}

// The running sshd reads the old files until it reloads, so they stay.
func TestScriptKeepsTheOldFilesWithoutAReload(t *testing.T) {
	t.Parallel()
	dir, out, err := runPlan(t, testPlan(t), map[string]string{"nokku_principals/root": "p\n"}, false, false)
	require.NoError(t, err, out)

	assert.False(t, ParseResult(out).Reloaded)
	assert.FileExists(t, filepath.Join(dir, "nokku_principals/root"))
}

func TestScriptRollsBackWhenSSHDRejects(t *testing.T) {
	t.Parallel()
	dir, out, err := runPlan(t, testPlan(t), map[string]string{
		"nokku_ca.pub":          "old-ca\n",
		"nokku_principals/root": "p\n",
	}, true, true)
	require.Error(t, err)

	assert.Contains(t, out, "rolled back")
	assert.Equal(t, "old-ca\n", readFile(t, filepath.Join(dir, "nokku_ca.pub")))
	assert.NoFileExists(t, filepath.Join(dir, "sshd_config.d/60-nokku.conf"), "a new file is removed again")
	assert.NoFileExists(t, filepath.Join(dir, "nokku_ca.pub.nokku-bak"))
	assert.FileExists(t, filepath.Join(dir, "nokku_principals/root"), "the old setup stays as it was")
	assert.False(t, ParseResult(out).Reloaded)
}

// A write that fails halfway, like on a full disk, rolls back earlier files.
func TestScriptRollsBackAFailedWrite(t *testing.T) {
	t.Parallel()
	dir, out, err := runPlan(t, testPlan(t), map[string]string{
		"nokku_ca.pub": "old-ca\n",
		// A directory where the staged file goes makes the write fail.
		"sshd_config.d/60-nokku.conf.nokku-tmp/x": "",
	}, false, true)
	require.Error(t, err)

	assert.Equal(t, "old-ca\n", readFile(t, filepath.Join(dir, "nokku_ca.pub")))
	assert.NoFileExists(t, filepath.Join(dir, "sshd_config.d/60-nokku.conf"))
	assert.False(t, ParseResult(out).Reloaded)
}

// A backup a dead run left behind must not be restored over the live file.
func TestScriptDropsStaleBackups(t *testing.T) {
	t.Parallel()
	dir, _, err := runPlan(t, testPlan(t), map[string]string{
		"nokku_ca.pub":           "live-ca\n",
		"nokku_ca.pub.nokku-bak": "stale-ca\n",
	}, true, true)
	require.Error(t, err)

	assert.Equal(t, "live-ca\n", readFile(t, filepath.Join(dir, "nokku_ca.pub")))
}

// runRemoveScript runs RemoveScript on a fake /etc/ssh with stubbed tools.
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
	assert.NoDirExists(t, filepath.Join(dir, "nokku_principals"), "a server set up the old way is cleaned too")
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
