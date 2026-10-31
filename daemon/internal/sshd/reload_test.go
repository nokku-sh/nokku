package sshd

import (
	"crypto/rand"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
	"github.com/nokku-sh/nokku/daemon/internal/state"
)

func trustsCA(srv *Server, ca testCA) bool {
	return srv.access.Load().trusts(string(ca.pub.Marshal()))
}

func TestSetAccessTrust(t *testing.T) {
	is := assert.New(t)
	first, second := newTestCA(t), newTestCA(t)
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())

	srv, err := New(nil)
	require.NoError(t, err, "new server without a CA")
	is.False(trustsCA(srv, first), "a server that never synced trusts no CA")

	srv.SetAccess(&state.Access{CA: string(ssh.MarshalAuthorizedKey(first.pub))})
	is.True(trustsCA(srv, first), "the synced CA is not trusted")

	srv.SetAccess(&state.Access{CA: string(ssh.MarshalAuthorizedKey(second.pub))})
	is.True(trustsCA(srv, second), "the new CA is not trusted")
	is.False(trustsCA(srv, first), "the replaced CA is still trusted")

	srv.SetAccess(&state.Access{})
	is.False(trustsCA(srv, second), "a target without a CA still trusts one")
}

// A restart trusts no CA when the active key on disk does not parse, so a sync that brings one must not either.
func TestUnreadableActiveCATrustsNone(t *testing.T) {
	is := assert.New(t)
	active, retired := newTestCA(t), newTestCA(t)
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	srv, err := New(nil)
	require.NoError(t, err)

	srv.SetAccess(&state.Access{CA: string(ssh.MarshalAuthorizedKey(active.pub))})
	srv.SetAccess(&state.Access{
		CA: "garbage",
		RetiredCAs: []*nokkuv1.RetiredCAKey{{
			PublicKey:    new(string(ssh.MarshalAuthorizedKey(retired.pub))),
			TrustedUntil: timestamppb.New(time.Now().Add(time.Hour)),
		}},
	})
	is.False(trustsCA(srv, active), "an unreadable CA kept the previous trust")
	is.False(trustsCA(srv, retired), "an unreadable CA still trusts the retired ones")
}

// An empty retired list, as sent after an emergency rollover, drops the old CA at once.
func TestRetiredCATrustedUntilDeadline(t *testing.T) {
	is := assert.New(t)
	active := newTestCA(t)
	retired := newTestCA(t)
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())

	srv, err := New(nil)
	require.NoError(t, err)

	activeKey := string(ssh.MarshalAuthorizedKey(active.pub))
	withRetired := func(until time.Time) *state.Access {
		return &state.Access{CA: activeKey, RetiredCAs: []*nokkuv1.RetiredCAKey{
			{PublicKey: new(string(ssh.MarshalAuthorizedKey(retired.pub))), TrustedUntil: timestamppb.New(until)},
			{PublicKey: new("garbage"), TrustedUntil: timestamppb.New(until)},
		}}
	}

	srv.SetAccess(&state.Access{CA: activeKey})
	is.False(trustsCA(srv, retired), "no retired CA synced yet")

	srv.SetAccess(withRetired(time.Now().Add(time.Hour)))
	is.True(trustsCA(srv, retired), "retired CA must be trusted before its deadline")
	is.True(trustsCA(srv, active), "active CA must stay trusted")

	srv.SetAccess(withRetired(time.Now().Add(-time.Minute)))
	is.False(trustsCA(srv, retired), "retired CA must not be trusted past its deadline")

	srv.SetAccess(withRetired(time.Now().Add(time.Hour)))
	srv.SetAccess(&state.Access{CA: activeKey})
	is.False(trustsCA(srv, retired), "an empty list must drop the retired CA at once")
	is.True(trustsCA(srv, active), "active CA must stay trusted")
}

func TestServerReloadRefreshesHostCerts(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	configDir := t.TempDir()
	t.Setenv("NOKKUD_DATA_DIR", configDir)

	srv, err := New(nil)
	must.NoError(err, "new server")
	srv.SetAccess(testAccess(t, ca))

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

// Every key exchange signs with the host key again, so a rekey after a reload still needs it.
func TestRekeyAfterReload(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	var srv *Server
	addr, closeFn := startTestServerOpts(t, ca, func(s *Server) { srv = s })
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
