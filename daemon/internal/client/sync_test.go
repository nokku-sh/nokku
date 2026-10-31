package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/user"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
	"github.com/nokku-sh/nokku/daemon/internal/sshd"
	"github.com/nokku-sh/nokku/daemon/internal/state"
)

// fakeCore refuses to sign host certificates, like a core whose CA was deactivated.
type fakeCore struct {
	nokkuv1connect.UnimplementedDaemonControlServiceHandler

	ca     string
	hostCA string
	signs  atomic.Int32
	// answer replaces the accepted sync answer when set.
	answer atomic.Pointer[nokkuv1.SyncDaemonResponse]
	// enrolled holds the last enroll request.
	enrolled atomic.Pointer[nokkuv1.EnrollDaemonRequest]
	// heartbeats gets the state version of the first heartbeat on each control stream.
	heartbeats chan int64
}

func (b *fakeCore) EnrollDaemon(
	_ context.Context,
	req *nokkuv1.EnrollDaemonRequest,
) (*nokkuv1.EnrollDaemonResponse, error) {
	b.enrolled.Store(req)
	return &nokkuv1.EnrollDaemonResponse{
		Id:          new("daemon-1"),
		TargetId:    new("target-1"),
		Status:      nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED.Enum(),
		Config:      &nokkuv1.DaemonConfig{Ephemeral: new(true)},
		AccessToken: new("session"),
	}, nil
}

func (b *fakeCore) SyncDaemon(
	context.Context,
	*nokkuv1.SyncDaemonRequest,
) (*nokkuv1.SyncDaemonResponse, error) {
	if res := b.answer.Load(); res != nil {
		return res, nil
	}
	return b.accepted(), nil
}

func (b *fakeCore) accepted() *nokkuv1.SyncDaemonResponse {
	return &nokkuv1.SyncDaemonResponse{
		Status:          nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED.Enum(),
		CaPublicKey:     &b.ca,
		HostCaPublicKey: &b.hostCA,
		StateVersion:    new(int64(7)),
		Principals: []*nokkuv1.AccountPrincipals{
			{Username: new("deploy"), CertPrincipals: []string{"subject-1"}},
		},
	}
}

func (b *fakeCore) SignHostCertificate(
	context.Context,
	*nokkuv1.SignHostCertificateRequest,
) (*nokkuv1.SignHostCertificateResponse, error) {
	b.signs.Add(1)
	return nil, connect.NewError(connect.CodeFailedPrecondition, "certificate authority is not active")
}

// Connect hangs up after the first heartbeat, so each stream reports one version.
func (b *fakeCore) Connect(_ context.Context, stream nokkuv1connect.DaemonControlServiceConnectServerStream) error {
	req, err := stream.Receive()
	if err != nil {
		return err
	}
	b.heartbeats <- req.GetHeartbeat().GetStateVersion()
	return nil
}

func newTestCAKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return string(ssh.MarshalAuthorizedKey(key))
}

func newSyncClient(t *testing.T, core *fakeCore) *Client {
	t.Helper()
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	require.NoError(t, paths.Verify())

	mux := http.NewServeMux()
	server := connect.NewServer()
	nokkuv1connect.RegisterDaemonControlServiceHandler(server, core)
	connecthttp.Mount(mux, server, connecthttp.WithReadMaxBytes(0))
	// The control stream goes both ways, which takes HTTP/2.
	api := httptest.NewUnstartedServer(mux)
	api.EnableHTTP2 = true
	api.StartTLS()
	t.Cleanup(api.Close)

	srv, err := sshd.New(nil)
	require.NoError(t, err)
	// Serve owns the host key, so it has to run for the key to be released.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		srv.Serve(ctx, l)
	}()
	t.Cleanup(func() {
		cancel()
		<-served
	})

	return &Client{
		state: state.New(state.Config{TargetID: "target-1"}),
		ctl: nokkuv1connect.NewDaemonControlServiceClient(
			connect.NewClient(connecthttp.NewTransport(api.Client(), api.URL)),
		),
		srv:     srv,
		sshAddr: netip.MustParseAddrPort(l.Addr().String()),
		renew:   make(chan struct{}, 1),
	}
}

// The revoke that must not get stuck: a new CA whose host certificate cannot be signed still replaces trust.
func TestSyncAppliesStateWithoutHostCert(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	core := &fakeCore{ca: newTestCAKey(t), hostCA: newTestCAKey(t)}
	c := newSyncClient(t, core)

	must.NoError(c.syncDaemon(t.Context()), "a sync must not fail on the host certificate")
	is.Equal([]string{"subject-1"}, c.state.Access().Principals["deploy"], "the grant did not land")
	is.Equal(core.ca, c.state.Access().CA, "the CA did not land")
	is.EqualValues(7, c.state.SavedVersion())
	is.Zero(core.signs.Load(), "the sync signed a host certificate itself")

	select {
	case <-c.renew:
	default:
		t.Fatal("a new host CA did not wake the certificate watcher")
	}
	must.Error(c.renewHostCerts(t.Context()), "the refused host certificate went unnoticed")
	_, err := os.Stat(paths.HostKeyCert())
	must.ErrorIs(err, os.ErrNotExist)

	// The same CA again changes nothing for the watcher.
	must.NoError(c.syncDaemon(t.Context()))
	select {
	case <-c.renew:
		t.Fatal("an unchanged CA woke the certificate watcher")
	default:
	}

	// The state survives a restart from disk.
	loaded, err := state.Load()
	must.NoError(err)
	is.Equal(core.ca, loaded.Access().CA)
	is.Equal([]string{"subject-1"}, loaded.Access().Principals["deploy"])
}

// An approval that is taken back must not leave the host serving what it synced while approved.
func TestSyncPendingDropsTrust(t *testing.T) {
	core := &fakeCore{ca: newTestCAKey(t)}
	c := newSyncClient(t, core)
	require.NoError(t, c.syncDaemon(t.Context()))
	require.NotEmpty(t, c.state.Access().Principals["deploy"])

	core.answer.Store(&nokkuv1.SyncDaemonResponse{Status: nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING.Enum()})
	require.NoError(t, c.syncDaemon(t.Context()))
	assert.Empty(t, c.state.Access().Principals["deploy"], "a pending daemon still honors its old grants")
	assert.Empty(t, c.state.Access().CA, "a pending daemon still trusts its old CA")

	loaded, err := state.Load()
	require.NoError(t, err)
	assert.Empty(t, loaded.Access().Principals["deploy"], "the old grants are still on disk")
}

// The core names the daemon after the host when a person named it, so enroll has to say what it is called.
func TestEnrollReportsTheHost(t *testing.T) {
	core := &fakeCore{ca: newTestCAKey(t)}
	c := newSyncClient(t, core)

	require.NoError(t, c.enroll(t.Context(), "token"))

	req := core.enrolled.Load()
	require.NotNil(t, req, "no enroll call reached the core")
	hostname, _ := os.Hostname()
	assert.Equal(t, hostname, req.GetMetadata()["hostname"])
	assert.Equal(t, "daemon-1", c.state.DaemonID)
	assert.True(t, c.state.Access().DaemonConfig.GetEphemeral(), "the enroll config is what the daemon keeps")
}

// Enrollment and access share one file, so a restart finds both and a new enrollment keeps nothing of the old.
func TestEnrollRestartReEnroll(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	core := &fakeCore{ca: newTestCAKey(t)}
	c := newSyncClient(t, core)

	must.NoError(c.enroll(t.Context(), "token"))
	must.NoError(c.syncDaemon(t.Context()))

	restarted, err := state.Load()
	must.NoError(err)
	is.Equal("daemon-1", restarted.DaemonID)
	is.Equal("target-1", restarted.TargetID)
	is.Equal("session", restarted.SessionToken)
	is.Equal(core.ca, restarted.Access().CA)
	is.Equal([]string{"subject-1"}, restarted.Access().Principals["deploy"])
	is.EqualValues(7, restarted.SavedVersion())

	must.NoError(c.enroll(t.Context(), "token"))
	reenrolled, err := state.Load()
	must.NoError(err)
	for _, s := range []*state.State{c.state, reenrolled} {
		is.Equal("daemon-1", s.DaemonID)
		is.Empty(s.Access().CA, "a new enrollment still trusts the old CA")
		is.Empty(s.Access().Principals, "a new enrollment still has the old grants")
		is.True(s.Access().DaemonConfig.GetEphemeral(), "the new enroll config was lost")
	}
}

// A rejection drops the enrollment and the access in one write. Only where the core is stays.
func TestRejectionDropsEnrollmentAndAccess(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	core := &fakeCore{ca: newTestCAKey(t)}
	c := newSyncClient(t, core)
	c.state.APIURL, c.state.APICA = "https://nokku.example", "private CA"
	must.NoError(c.enroll(t.Context(), "token"))
	must.NoError(c.syncDaemon(t.Context()))

	core.answer.Store(&nokkuv1.SyncDaemonResponse{Status: nokkuv1.DaemonStatus_DAEMON_STATUS_REJECTED.Enum()})
	must.ErrorIs(c.syncDaemon(t.Context()), errDaemonRejected)

	loaded, err := state.Load()
	must.NoError(err)
	is.Equal(state.Config{APIURL: "https://nokku.example", APICA: "private CA"}, loaded.Config)
	is.Empty(loaded.Access().CA)
	is.Empty(loaded.Access().Principals)
}

// The heartbeat reports what is on disk, so after a failed save the core keeps asking for a sync until one lands.
func TestHeartbeatReportsTheSavedVersion(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	core := &fakeCore{ca: newTestCAKey(t), heartbeats: make(chan int64, 1)}
	c := newSyncClient(t, core)
	reported := func() int64 {
		_ = c.runControlStream(t.Context())
		return <-core.heartbeats
	}

	must.NoError(c.syncDaemon(t.Context()))
	is.EqualValues(7, reported())

	// A directory in its place fails every save, root or not.
	must.NoError(os.Remove(paths.StateFile()))
	must.NoError(os.Mkdir(paths.StateFile(), 0o700))
	next := core.accepted()
	next.StateVersion = new(int64(8))
	core.answer.Store(next)
	must.Error(c.syncDaemon(t.Context()), "the failed save went unnoticed")
	is.EqualValues(8, c.state.Access().StateVersion, "the sync did not apply because its save failed")
	is.EqualValues(7, reported(), "a version that never reached the disk was reported")

	must.NoError(os.Remove(paths.StateFile()))
	must.NoError(c.syncDaemon(t.Context()))
	is.EqualValues(8, reported())
}

// Right after a sync whose CA key does not parse, the old CA opens nothing, the same as after a restart.
func TestSyncWithUnreadableCAClosesTheOldCA(t *testing.T) {
	must := require.New(t)
	cur, err := user.Current()
	must.NoError(err)
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	must.NoError(err)
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	must.NoError(err)

	core := &fakeCore{}
	c := newSyncClient(t, core)
	grant := func(caKey string) *nokkuv1.SyncDaemonResponse {
		res := core.accepted()
		res.CaPublicKey = &caKey
		res.Principals = []*nokkuv1.AccountPrincipals{{Username: &cur.Username, CertPrincipals: []string{"subject-1"}}}
		return res
	}
	core.answer.Store(grant(string(ssh.MarshalAuthorizedKey(caSigner.PublicKey()))))
	must.NoError(c.syncDaemon(t.Context()))

	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	must.NoError(err)
	userSigner, err := ssh.NewSignerFromKey(userPriv)
	must.NoError(err)
	cert := &ssh.Certificate{
		Key:             userSigner.PublicKey(),
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"subject-1"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	must.NoError(cert.SignCert(rand.Reader, caSigner))
	certSigner, err := ssh.NewCertSigner(cert, userSigner)
	must.NoError(err)
	login := func() (*ssh.Client, error) {
		return ssh.Dial("tcp", c.sshAddr.String(), &ssh.ClientConfig{
			User:            cur.Username,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 - test server
			Timeout:         10 * time.Second,
		})
	}

	client, err := login()
	must.NoError(err, "the synced CA does not log in")
	defer client.Close()
	sess, err := client.NewSession()
	must.NoError(err)
	defer sess.Close()
	must.NoError(sess.Start("sleep 30"))
	gone := make(chan struct{})
	go func() {
		_ = client.Wait()
		close(gone)
	}()

	core.answer.Store(grant("garbage"))
	must.NoError(c.syncDaemon(t.Context()))
	select {
	case <-gone:
	case <-time.After(5 * time.Second):
		t.Fatal("the session of the old CA stayed open")
	}
	_, err = login()
	must.Error(err, "the old CA still logs in")
}
