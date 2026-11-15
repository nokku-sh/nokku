package sshd

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/daemon/internal/cgroup"
	"github.com/nokku-sh/nokku/daemon/internal/state"
)

// sessionGroups needs a cgroup v2 this user may write, like a terminal's scope under systemd. CI has none, the
// container of task daemon:test:root does.
func sessionGroups(t *testing.T) *cgroup.Tree {
	t.Helper()
	groups := cgroup.Open(t.Context())
	if groups == nil {
		t.Skip("no writable cgroup v2 here")
	}
	// Ends what a failed run left, and removes the groups that emptied.
	t.Cleanup(func() { groups.KillExcept(func(string) bool { return false }) })
	return groups
}

// leaveBehind starts a process the way a user would who wants it to outlive the session.
func leaveBehind(t *testing.T, client *ssh.Client) (pid string) {
	t.Helper()
	sess, err := client.NewSession()
	require.NoError(t, err)
	defer sess.Close()
	out, err := sess.Output("setsid nohup sleep 300 >/dev/null 2>&1 & echo $!")
	require.NoError(t, err)
	return strings.TrimSpace(string(out))
}

func processAlive(pid string) bool {
	stat, err := os.ReadFile("/proc/" + pid + "/stat")
	// A killed process is a zombie until its new parent reaps it.
	return err == nil && !strings.Contains(string(stat), ") Z ")
}

// checkRevokeKills ends the client's connection first. A hangup must leave the process alone, like sshd does,
// and only a revoke with the rule on may end it.
func checkRevokeKills(t *testing.T, srv *Server, client *ssh.Client, granted *state.Access) {
	t.Helper()
	pid := leaveBehind(t, client)
	require.True(t, processAlive(pid), "the detached process never ran")
	require.NoError(t, client.Close())
	require.Eventually(t, srv.Idle, 5*time.Second, 10*time.Millisecond, "the connection stayed open")
	still := func(why string) {
		t.Helper()
		assert.Never(t, func() bool { return !processAlive(pid) }, 200*time.Millisecond, 20*time.Millisecond, why)
	}
	still("a hangup killed a detached process")

	ruleOn := *granted
	ruleOn.DaemonConfig = &nokkuv1.DaemonConfig{KillOnRevoke: new(true)}
	srv.SetAccess(&ruleOn)
	srv.DropRevoked()
	still("a sync that revoked nothing killed a process")

	// An older core and a deleted server send no rule, which reads as off.
	ruleUnset := *granted
	ruleUnset.Principals = nil
	ruleUnset.DaemonConfig = nil
	srv.SetAccess(&ruleUnset)
	srv.DropRevoked()
	still("a revoke killed a process with the rule off")

	revoked := ruleOn
	revoked.Principals = nil
	srv.SetAccess(&revoked)
	srv.DropRevoked()
	assert.Eventually(t, func() bool { return !processAlive(pid) }, 5*time.Second, 10*time.Millisecond,
		"a detached process outlived the revoke of its user")
}

func TestRevokeKillsWhatASessionLeftBehind(t *testing.T) {
	groups := sessionGroups(t)
	ca := newTestCA(t)
	log, events := auditLog()
	var srv *Server
	addr, closeFn := startTestServerOpts(t, ca, withLog(log), func(s *Server) { srv, s.groups = s, groups })
	defer closeFn()
	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	require.NoError(t, err)

	checkRevokeKills(t, srv, client, testAccess(t, ca))

	assert.Contains(t, events(), eventRevokeKill, "the kill is missing from the audit log")
}

// A request that was already queued can start its process after the revoke ran.
func TestProcessStartedAfterTheRevokeIsKilled(t *testing.T) {
	groups := sessionGroups(t)
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	srv, err := New(nil, nil, groups)
	require.NoError(t, err)
	revoked := testAccess(t, newTestCA(t))
	revoked.Principals = nil
	revoked.DaemonConfig = &nokkuv1.DaemonConfig{KillOnRevoke: new(true)}
	srv.SetAccess(revoked)
	srv.DropRevoked()

	cmd := exec.CommandContext(t.Context(), "sleep", "300")
	require.NoError(t, srv.start(testPrincipal, cmd))

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
		require.ErrorContains(t, err, "killed")
	case <-time.After(5 * time.Second):
		t.Fatal("a process of a revoked principal kept running")
	}
}
