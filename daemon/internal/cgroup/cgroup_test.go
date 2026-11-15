package cgroup

import (
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeGroup is a plain directory that reads like a cgroup with or without processes.
func fakeGroup(t *testing.T, tree *Tree, owner string, alive bool) string {
	t.Helper()
	group := filepath.Join(tree.dir, owner)
	require.NoError(t, os.Mkdir(group, 0o755))
	events := "populated 0\nfrozen 0\n"
	if alive {
		events = "populated 1\nfrozen 0\n"
	}
	require.NoError(t, os.WriteFile(filepath.Join(group, "cgroup.events"), []byte(events), 0o600))
	return group
}

func TestKillExceptPicksTheGroupsToKill(t *testing.T) {
	tree := &Tree{dir: t.TempDir()}
	kept := fakeGroup(t, tree, "kept", true)
	revoked := fakeGroup(t, tree, "revoked", true)
	idle := fakeGroup(t, tree, "revoked-idle", false)

	killed := tree.KillExcept(func(owner string) bool { return owner == "kept" })

	assert.Equal(t, []string{"revoked"}, killed, "only a group with processes counts as killed")
	assert.FileExists(t, filepath.Join(revoked, killFile), "the revoked owner's group was not killed")
	assert.NoFileExists(t, filepath.Join(kept, killFile), "an owner with access lost its processes")
	// rmdir fails on the fake, its events file is in the way. What counts is that nothing wrote the kill.
	assert.NoFileExists(t, filepath.Join(idle, killFile), "an empty group counted as killed")
}

// A group that cannot be read may still hold processes.
func TestKillExceptKillsWhatItCannotRead(t *testing.T) {
	tree := &Tree{dir: t.TempDir()}
	unreadable := fakeGroup(t, tree, "revoked", true)
	require.NoError(t, os.Remove(filepath.Join(unreadable, "cgroup.events")))

	assert.Equal(t, []string{"revoked"}, tree.KillExcept(func(string) bool { return false }))
	assert.FileExists(t, filepath.Join(unreadable, killFile))
}

// The owner becomes a directory name under the tree.
func TestStartRefusesNamesThatLeaveTheTree(t *testing.T) {
	tree := &Tree{dir: t.TempDir()}
	for _, owner := range []string{"", ".", "..", "../up", "a/b", ".probe", "nul\x00"} {
		err := tree.Start(exec.CommandContext(t.Context(), "true"), owner)
		require.ErrorContains(t, err, "no directory name", "owner %q", owner)
	}
	entries, err := os.ReadDir(tree.dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "a refused name still made a directory")
}

func TestOpenAtRefusesWhatIsNoCgroup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nokkud")
	_, err := openAt(t.Context(), dir)
	require.ErrorContains(t, err, killFile)
	assert.NoDirExists(t, dir, "the directory of a failed open stays behind")
}

// realTree needs a cgroup v2 this user may write, like a terminal's scope under systemd. CI has none.
func realTree(t *testing.T) *Tree {
	t.Helper()
	own, err := ownGroup()
	if err != nil {
		t.Skipf("no cgroup v2: %v", err)
	}
	dir := filepath.Join(own, "nokkud-test-"+strings.ToLower(rand.Text()))
	tree, err := openAt(t.Context(), dir)
	if err != nil {
		t.Skipf("no writable cgroup v2 with %s: %v", killFile, err)
	}
	t.Cleanup(func() {
		assert.Eventually(t, func() bool {
			tree.KillExcept(func(string) bool { return false })
			return os.Remove(dir) == nil
		}, 5*time.Second, 20*time.Millisecond, "the test tree stayed behind")
	})
	return tree
}

// startDetached leaves a process behind the way a user would, its parent gone and in a session of its own.
func startDetached(t *testing.T, tree *Tree, owner string) (pid string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", "setsid nohup sleep 300 >/dev/null 2>&1 & echo $!")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	var out strings.Builder
	cmd.Stdout = &out
	require.NoError(t, tree.Start(cmd, owner))
	require.NoError(t, cmd.Wait())
	return strings.TrimSpace(out.String())
}

func alive(pid string) bool {
	stat, err := os.ReadFile("/proc/" + pid + "/stat")
	// A killed process is a zombie until its new parent reaps it.
	return err == nil && !strings.Contains(string(stat), ") Z ")
}

func TestKillEndsDetachedProcesses(t *testing.T) {
	tree := realTree(t)
	kept := startDetached(t, tree, "kept")
	revoked := startDetached(t, tree, "revoked")
	procs, err := os.ReadFile(filepath.Join(tree.dir, "revoked", "cgroup.procs"))
	require.NoError(t, err)
	require.Contains(t, strings.Fields(string(procs)), revoked, "the detached process left its group")

	killed := tree.KillExcept(func(owner string) bool { return owner == "kept" })

	assert.Equal(t, []string{"revoked"}, killed)
	assert.Eventually(t, func() bool { return !alive(revoked) }, 5*time.Second, 10*time.Millisecond,
		"a detached process outlived the kill of its group")
	assert.True(t, alive(kept), "the kill reached an owner with access")
}

// A daemon that restarts finds the groups of its last run, alive or not.
func TestOpenAtKeepsGroupsWithProcesses(t *testing.T) {
	tree := realTree(t)
	pid := startDetached(t, tree, "busy")
	require.NoError(t, os.Mkdir(filepath.Join(tree.dir, "idle"), 0o755))

	again, err := openAt(t.Context(), tree.dir)
	require.NoError(t, err)

	assert.Equal(t, []string{"busy"}, again.groups(), "only the empty group goes at a start")
	assert.True(t, alive(pid))
	assert.Equal(t, []string{"busy"}, again.KillExcept(func(string) bool { return false }),
		"a revoke after the restart still finds the group")
}
