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
	"github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
	"github.com/nokku-sh/nokku/daemon/internal/report"
	"github.com/nokku-sh/nokku/daemon/internal/sshd"
	"github.com/nokku-sh/nokku/daemon/internal/state"
)

const (
	testTarget  = "6f1c2b4e-8a3d-4c5e-9f70-1a2b3c4d5e6f"
	testSubject = "11111111-2222-4333-8444-555555555555"
)

// fakeCore won't sign host certificates, like a core whose CA is deactivated.
type fakeCore struct {
	nokkuv1connect.UnimplementedDaemonControlServiceHandler

	ca     string
	hostCA string
	signs  atomic.Int32
	// answer replaces the accepted sync answer when set.
	answer   atomic.Pointer[nokkuv1.SyncDaemonResponse]
	enrolled atomic.Pointer[nokkuv1.EnrollDaemonRequest]
	// heartbeats gets the state hash of each stream's first heartbeat.
	heartbeats chan string
	syncs      atomic.Int32
	// updates are the hashes Connect sends as state updates before it hangs up.
	updates atomic.Pointer[[][]byte]
}

func (b *fakeCore) EnrollDaemon(
	_ context.Context,
	req *nokkuv1.EnrollDaemonRequest,
) (*nokkuv1.EnrollDaemonResponse, error) {
	b.enrolled.Store(req)
	return &nokkuv1.EnrollDaemonResponse{
		Id:          new("daemon-1"),
		TargetId:    new(testTarget),
		Status:      nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED.Enum(),
		Config:      &nokkuv1.DaemonConfig{Ephemeral: new(true)},
		AccessToken: new("session"),
	}, nil
}

func (b *fakeCore) SyncDaemon(
	context.Context,
	*nokkuv1.SyncDaemonRequest,
) (*nokkuv1.SyncDaemonResponse, error) {
	b.syncs.Add(1)
	if res := b.answer.Load(); res != nil {
		return res, nil
	}
	return b.accepted(), nil
}

func (b *fakeCore) accepted() *nokkuv1.SyncDaemonResponse {
	return &nokkuv1.SyncDaemonResponse{
		Status:          nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED.Enum(),
		UserCaPublicKey: &b.ca,
		HostCaPublicKey: &b.hostCA,
		StateHash:       []byte("7"),
		Principals: []*nokkuv1.AccountPrincipals{
			{Username: new("deploy"), CertPrincipals: []string{principal("deploy")}},
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

// Connect hangs up after one heartbeat, so each stream reports one version.
func (b *fakeCore) Connect(_ context.Context, stream nokkuv1connect.DaemonControlServiceConnectServerStream) error {
	req, err := stream.Receive()
	if err != nil {
		return err
	}
	b.heartbeats <- string(req.GetHeartbeat().GetStateHash())
	if updates := b.updates.Load(); updates != nil {
		for _, hash := range *updates {
			if err = stream.Send(&nokkuv1.ConnectResponse{
				Msg: &nokkuv1.ConnectResponse_StateUpdate{StateUpdate: &nokkuv1.StateUpdate{StateHash: hash}},
			}); err != nil {
				return err
			}
		}
	}
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

	srv, err := sshd.New(nil, nil)
	require.NoError(t, err)
	// Serve owns the host key, so it has to run for the key to be released.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
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
		state: state.New(state.Config{TargetID: testTarget}),
		ctl: nokkuv1connect.NewDaemonControlServiceClient(
			connect.NewClient(connecthttp.NewTransport(api.Client(), api.URL)),
		),
		srv:     srv,
		sshAddr: netip.MustParseAddrPort(l.Addr().String()),
		renew:   make(chan struct{}, 1),
		reports: report.Open(paths.ReportsFile()),
	}
}

// A revoke must not get stuck: a new CA applies even with no host certificate.
func TestSyncAppliesStateWithoutHostCert(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	core := &fakeCore{ca: newTestCAKey(t), hostCA: newTestCAKey(t)}
	c := newSyncClient(t, core)

	must.NoError(c.syncDaemon(t.Context()), "a sync must not fail on the host certificate")
	is.Equal([]string{principal("deploy")}, c.state.Access().Principals["deploy"], "the grant did not land")
	is.Equal(core.ca, c.state.Access().UserCA, "the CA did not land")
	is.Equal("7", string(c.state.Saved().StateHash))
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

	loaded, err := state.Load()
	must.NoError(err)
	is.Equal(core.ca, loaded.Access().UserCA)
	is.Equal([]string{principal("deploy")}, loaded.Access().Principals["deploy"])
}

// An approval taken back must not leave the host serving its old grants.
func TestSyncPendingDropsTrust(t *testing.T) {
	core := &fakeCore{ca: newTestCAKey(t)}
	c := newSyncClient(t, core)
	require.NoError(t, c.syncDaemon(t.Context()))
	require.NotEmpty(t, c.state.Access().Principals["deploy"])

	core.answer.Store(&nokkuv1.SyncDaemonResponse{Status: nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING.Enum()})
	require.NoError(t, c.syncDaemon(t.Context()))
	assert.Empty(t, c.state.Access().Principals["deploy"], "a pending daemon still honors its old grants")
	assert.Empty(t, c.state.Access().UserCA, "a pending daemon still trusts its old CA")

	loaded, err := state.Load()
	require.NoError(t, err)
	assert.Empty(t, loaded.Access().Principals["deploy"], "the old grants are still on disk")
}

// The core names the daemon after a host a person named, so enroll reports it.
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

// Enrollment and access share a file: a restart finds both, re-enroll resets.
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
	is.Equal(testTarget, restarted.TargetID)
	is.Equal("session", restarted.SessionToken)
	is.Equal(core.ca, restarted.Access().UserCA)
	is.Equal([]string{principal("deploy")}, restarted.Access().Principals["deploy"])
	is.Equal("7", string(restarted.Saved().StateHash))

	must.NoError(c.enroll(t.Context(), "token"))
	reenrolled, err := state.Load()
	must.NoError(err)
	for _, s := range []*state.State{c.state, reenrolled} {
		is.Equal("daemon-1", s.DaemonID)
		is.Empty(s.Access().UserCA, "a new enrollment still trusts the old CA")
		is.Empty(s.Access().Principals, "a new enrollment still has the old grants")
		is.True(s.Access().DaemonConfig.GetEphemeral(), "the new enroll config was lost")
	}
}

// One write drops enrollment and access. Only where the core is stays.
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
	is.Empty(loaded.Access().UserCA)
	is.Empty(loaded.Access().Principals)
}

// The heartbeat reports what is on disk, so a failed save gets synced again.
func TestHeartbeatReportsTheSavedState(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	core := &fakeCore{ca: newTestCAKey(t), heartbeats: make(chan string, 1)}
	c := newSyncClient(t, core)
	reported := func() string {
		_ = c.runControlStream(t.Context())
		return <-core.heartbeats
	}

	must.NoError(c.syncDaemon(t.Context()))
	is.Equal("7", reported())

	// A directory in its place fails every save, root or not.
	must.NoError(os.Remove(paths.StateFile()))
	must.NoError(os.Mkdir(paths.StateFile(), 0o700))
	next := core.accepted()
	next.StateHash = []byte("8")
	core.answer.Store(next)
	must.Error(c.syncDaemon(t.Context()), "the failed save went unnoticed")
	is.Equal("8", string(c.state.Access().StateHash), "the sync did not apply because its save failed")
	is.Equal("7", reported(), "a state that never reached the disk was reported")

	must.NoError(os.Remove(paths.StateFile()))
	must.NoError(c.syncDaemon(t.Context()))
	is.Equal("8", reported())
}

// The core says what the daemon should hold. With that on disk there is nothing to fetch.
func TestStateUpdateFetchesOnlyWhatIsNew(t *testing.T) {
	core := &fakeCore{ca: newTestCAKey(t), heartbeats: make(chan string, 1)}
	c := newSyncClient(t, core)
	held := core.accepted()
	held.StateHash = []byte("held")
	core.answer.Store(held)
	require.NoError(t, c.syncDaemon(t.Context()))

	for _, tt := range []struct {
		name    string
		update  []byte
		fetches int32
	}{
		{"what it holds", []byte("held"), 0},
		{"something else", []byte("new"), 1},
		{"no hash at all", nil, 1},
	} {
		before := core.syncs.Load()
		core.updates.Store(&[][]byte{tt.update})
		_ = c.runControlStream(t.Context())
		<-core.heartbeats
		assert.Equal(t, tt.fetches, core.syncs.Load()-before, "an update with %s", tt.name)
	}
}

// With nothing to trigger it, a daemon still syncs now and then.
func TestResyncKeepsSyncing(t *testing.T) {
	core := &fakeCore{ca: newTestCAKey(t)}
	c := newSyncClient(t, core)
	ctx, stop := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.resync(ctx, 10*time.Millisecond)
	}()
	assert.Eventually(t, func() bool { return core.syncs.Load() >= 3 }, 5*time.Second, 5*time.Millisecond,
		"the daemon stopped syncing on its own")
	stop()
	<-done
}

// A sync with an unparsable CA key closes the old CA, just as a restart would.
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
		res.UserCaPublicKey = &caKey
		res.Principals = []*nokkuv1.AccountPrincipals{
			{Username: &cur.Username, CertPrincipals: []string{principal(cur.Username)}},
		}
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
		ValidPrincipals: []string{principal(cur.Username)},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	must.NoError(cert.SignCert(rand.Reader, caSigner))
	certSigner, err := ssh.NewCertSigner(cert, userSigner)
	must.NoError(err)
	login := func() (*ssh.Client, error) {
		return ssh.Dial("tcp", c.sshAddr.String(), &ssh.ClientConfig{
			User:            cur.Username,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106
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

// A sync keeps only principals for this server and the account, so tests use real ones.
func principal(username string) string { return login.Principal(testSubject, testTarget, username) }
