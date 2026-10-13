package sshd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestServerForceCommand(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	auth := userCertOpts(t, ca, func(c *ssh.Certificate) {
		c.CriticalOptions = map[string]string{"force-command": "echo forced"}
	}, testPrincipal)

	client, err := dial(t, addr, currentUser(t), auth)
	must.NoError(err)
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err)
	defer sess.Close()

	out, err := sess.Output("echo original")
	must.NoError(err)
	is.Equal("forced\n", string(out))
}

// Restricted-command wrappers like git-shell and rrsync read the client's request from SSH_ORIGINAL_COMMAND.
func TestServerForceCommandOriginalCommand(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	auth := userCertOpts(t, ca, func(c *ssh.Certificate) {
		c.CriticalOptions = map[string]string{"force-command": `printf '[%s]' "$SSH_ORIGINAL_COMMAND"`}
	}, testPrincipal)

	client, err := dial(t, addr, currentUser(t), auth)
	must.NoError(err)
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err)
	out, err := sess.Output("git-upload-pack 'repo.git'")
	must.NoError(err)
	is.Equal("[git-upload-pack 'repo.git']", string(out))
	_ = sess.Close()

	// A shell request asked for nothing, so the variable stays unset like in sshd.
	sess, err = client.NewSession()
	must.NoError(err)
	defer sess.Close()
	out, err = sess.Output("")
	must.NoError(err)
	is.Equal("[]", string(out))
}

func TestServerForceCommandSubsystem(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	auth := userCertOpts(t, ca, func(c *ssh.Certificate) {
		c.CriticalOptions = map[string]string{"force-command": "echo forced"}
	}, testPrincipal)

	client, err := dial(t, addr, currentUser(t), auth)
	must.NoError(err)
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err)
	defer sess.Close()

	err = sess.RequestSubsystem("sftp")
	must.Error(err, "subsystem unexpectedly allowed with force-command")
	must.ErrorContains(err, "failed")
}

// Like sshd, the client cannot signal a forced command.
func TestServerForceCommandRefusesSignal(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	auth := userCertOpts(t, ca, func(c *ssh.Certificate) {
		c.CriticalOptions = map[string]string{"force-command": "sleep 30"}
	}, testPrincipal)
	client, err := dial(t, addr, currentUser(t), auth)
	must.NoError(err)
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err)
	defer sess.Close()
	must.NoError(sess.Start(""))

	ok, err := sess.SendRequest("signal", true, ssh.Marshal(struct{ Signal string }{"TERM"}))
	must.NoError(err)
	must.False(ok, "a forced command took a signal from the client")
}
