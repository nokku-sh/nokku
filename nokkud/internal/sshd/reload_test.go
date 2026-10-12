package sshd

import (
	"crypto"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/tpm"
	"github.com/nokku-sh/nokku/nokkud/internal/paths"
)

func TestSetTrust(t *testing.T) {
	is := assert.New(t)
	first, second := newTestCA(t), newTestCA(t)
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())

	srv, err := New(Options{Principals: func(string) []string { return nil }})
	require.NoError(t, err, "new server without a CA")
	defer srv.hostKeyDev.Close()
	is.False(srv.trustedCA(first.pub), "a server that never synced trusts no CA")

	srv.SetTrust(string(ssh.MarshalAuthorizedKey(first.pub)), nil)
	is.True(srv.trustedCA(first.pub), "the synced CA is not trusted")

	srv.SetTrust("garbage", nil)
	is.True(srv.trustedCA(first.pub), "an unreadable CA dropped the previous trust")

	srv.SetTrust(string(ssh.MarshalAuthorizedKey(second.pub)), nil)
	is.True(srv.trustedCA(second.pub), "the new CA is not trusted")
	is.False(srv.trustedCA(first.pub), "the replaced CA is still trusted")

	srv.SetTrust("", nil)
	is.False(srv.trustedCA(second.pub), "a target without a CA still trusts one")
}

// An empty retired list, as sent after an emergency rollover, drops the old CA at once.
func TestRetiredCATrustedUntilDeadline(t *testing.T) {
	is := assert.New(t)
	active := newTestCA(t)
	retired := newTestCA(t)
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())

	srv, err := New(Options{Principals: func(string) []string { return nil }})
	require.NoError(t, err)
	defer srv.hostKeyDev.Close()

	activeKey := string(ssh.MarshalAuthorizedKey(active.pub))
	retiredKey := func(until time.Time) []*nokkuv1.RetiredCAKey {
		return []*nokkuv1.RetiredCAKey{
			{PublicKey: new(string(ssh.MarshalAuthorizedKey(retired.pub))), TrustedUntil: timestamppb.New(until)},
			{PublicKey: new("garbage"), TrustedUntil: timestamppb.New(until)},
		}
	}

	srv.SetTrust(activeKey, nil)
	is.False(srv.trustedCA(retired.pub), "no retired CA synced yet")

	srv.SetTrust(activeKey, retiredKey(time.Now().Add(time.Hour)))
	is.True(srv.trustedCA(retired.pub), "retired CA must be trusted before its deadline")
	is.True(srv.trustedCA(active.pub), "active CA must stay trusted")

	srv.SetTrust(activeKey, retiredKey(time.Now().Add(-time.Minute)))
	is.False(srv.trustedCA(retired.pub), "retired CA must not be trusted past its deadline")

	srv.SetTrust(activeKey, retiredKey(time.Now().Add(time.Hour)))
	srv.SetTrust(activeKey, nil)
	is.False(srv.trustedCA(retired.pub), "an empty list must drop the retired CA at once")
	is.True(srv.trustedCA(active.pub), "active CA must stay trusted")
}

func TestServerReloadRefreshesHostCerts(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	configDir := t.TempDir()
	t.Setenv("NOKKUD_DATA_DIR", configDir)

	srv, err := New(Options{
		Principals: func(username string) []string {
			if username == currentUser(t) {
				return []string{testPrincipal}
			}
			return nil
		},
	})
	must.NoError(err, "new server")
	srv.SetTrust(string(ssh.MarshalAuthorizedKey(ca.pub)), nil)
	defer srv.hostKeyDev.Close()

	// Sign the host key New generated and write the cert next to it, as RenewHostCerts would.
	pubData, err := os.ReadFile(paths.HostKeyPub())
	must.NoError(err)
	hostPub, _, _, _, err := ssh.ParseAuthorizedKey(pubData)
	must.NoError(err)
	cert := &ssh.Certificate{
		Key:         hostPub,
		CertType:    ssh.HostCert,
		KeyId:       "host-test",
		ValidAfter:  0,
		ValidBefore: ssh.CertTimeInfinity,
	}
	must.NoError(cert.SignCert(rand.Reader, ca.signer))
	certPath := paths.HostKeyCert()
	must.NoError(os.WriteFile(certPath, ssh.MarshalAuthorizedKey(cert), 0o644))

	srv.Reload()

	// A host cert signer's PublicKey() returns the certificate itself.
	srv.mu.RLock()
	cfg := srv.cfg
	srv.mu.RUnlock()
	_, hasCert := hostPublicKey(t, cfg).(*ssh.Certificate)
	is.True(hasCert, "reload did not adopt the host certificate")
}

func hostPublicKey(t *testing.T, cfg *ssh.ServerConfig) ssh.PublicKey {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	go func() {
		nc, acceptErr := l.Accept()
		if acceptErr != nil {
			return
		}
		defer nc.Close()
		_, _, _, _ = ssh.NewServerConn(nc, cfg)
	}()
	c1, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	defer c1.Close()
	var got ssh.PublicKey
	_, _, _, _ = ssh.NewClientConn(c1, "pipe", &ssh.ClientConfig{
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return errors.New("done")
		},
		HostKeyAlgorithms: []string{ssh.CertAlgoECDSA256v01},
	})
	require.NotNil(t, got, "no host key presented")
	return got
}

// closingSigner cannot sign once closed, like a key held in a TPM.
type closingSigner struct {
	tpm.Signer

	closed atomic.Bool
}

func (c *closingSigner) Close() error {
	c.closed.Store(true)
	return c.Signer.Close()
}

func (c *closingSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if c.closed.Load() {
		return nil, errors.New("host key is closed")
	}
	return c.Signer.Sign(rand, digest, opts)
}

// Every key exchange signs with the host key again, so a rekey after a reload needs it open.
func TestReloadKeepsHostKeyOpen(t *testing.T) {
	must := require.New(t)
	open := newHostSigner
	newHostSigner = func(opts tpm.SignerOptions) (tpm.Signer, error) {
		signer, err := open(opts)
		if err != nil {
			return nil, err
		}
		return &closingSigner{Signer: signer}, nil
	}
	t.Cleanup(func() { newHostSigner = open })

	ca := newTestCA(t)
	var srv *Server
	addr, closeFn := startTestServerOpts(t, ca, Options{}, func(s *Server) { srv = s })
	defer closeFn()

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		RekeyThreshold:  1024,
		User:            currentUser(t),
		Auth:            []ssh.AuthMethod{userCert(t, ca, testPrincipal)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 - test server
		Timeout:         10 * time.Second,
	})
	must.NoError(err, "dial")
	defer client.Close()

	srv.Reload()

	sess, err := client.NewSession()
	must.NoError(err, "session after reload")
	defer sess.Close()
	out, err := sess.Output("head -c 200000 /dev/zero")
	must.NoError(err, "the connection broke when it rekeyed after a reload")
	must.Len(out, 200000)
}
