package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect/v2"
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

	ca    string
	signs atomic.Int32
	// pending answers like a core that has not approved the daemon.
	pending atomic.Bool
	// enrolled holds the last enroll request.
	enrolled atomic.Pointer[nokkuv1.EnrollDaemonRequest]
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
	if b.pending.Load() {
		return &nokkuv1.SyncDaemonResponse{Status: nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING.Enum()}, nil
	}
	return &nokkuv1.SyncDaemonResponse{
		Status:       nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED.Enum(),
		CaPublicKey:  &b.ca,
		StateVersion: new(int64(7)),
		Principals: []*nokkuv1.AccountPrincipals{
			{Username: new("deploy"), CertPrincipals: []string{"subject-1"}},
		},
	}, nil
}

func (b *fakeCore) SignHostCertificate(
	context.Context,
	*nokkuv1.SignHostCertificateRequest,
) (*nokkuv1.SignHostCertificateResponse, error) {
	b.signs.Add(1)
	return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("certificate authority is not active"))
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
	mux.Handle(nokkuv1connect.NewDaemonControlServiceHandler(core))
	api := httptest.NewServer(mux)
	t.Cleanup(api.Close)

	cache := state.NewCache()
	srv, err := sshd.New(sshd.Options{Principals: cache.CertPrincipals})
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
		cache:  cache,
		config: &state.Config{TargetID: "target-1"},
		ctl:    nokkuv1connect.NewDaemonControlServiceClient(api.Client(), api.URL),
		srv:    srv,
		renew:  make(chan struct{}, 1),
	}
}

// The revoke that must not get stuck: a new CA whose host certificate cannot be signed still replaces trust.
func TestSyncAppliesStateWithoutHostCert(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	core := &fakeCore{ca: newTestCAKey(t)}
	c := newSyncClient(t, core)

	must.NoError(c.syncDaemon(t.Context()), "a sync must not fail on the host certificate")
	is.Equal([]string{"subject-1"}, c.cache.CertPrincipals("deploy"), "the grant did not land")
	active, _ := c.cache.CAs()
	is.Equal(core.ca, active, "the CA did not land")
	is.EqualValues(7, c.cache.GetStateVersion())
	is.Zero(core.signs.Load(), "the sync signed a host certificate itself")

	select {
	case <-c.renew:
	default:
		t.Fatal("a new CA did not wake the certificate watcher")
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
	loaded := state.NewCache()
	must.NoError(loaded.Load())
	active, _ = loaded.CAs()
	is.Equal(core.ca, active)
	is.Equal([]string{"subject-1"}, loaded.CertPrincipals("deploy"))
}

// An approval that is taken back must not leave the host serving what it synced while approved.
func TestSyncPendingDropsTrust(t *testing.T) {
	core := &fakeCore{ca: newTestCAKey(t)}
	c := newSyncClient(t, core)
	require.NoError(t, c.syncDaemon(t.Context()))
	require.NotEmpty(t, c.cache.CertPrincipals("deploy"))

	core.pending.Store(true)
	require.NoError(t, c.syncDaemon(t.Context()))
	assert.Empty(t, c.cache.CertPrincipals("deploy"), "a pending daemon still honors its old grants")
	active, _ := c.cache.CAs()
	assert.Empty(t, active, "a pending daemon still trusts its old CA")

	loaded := state.NewCache()
	require.NoError(t, loaded.Load())
	assert.Empty(t, loaded.CertPrincipals("deploy"), "the old grants are still on disk")
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
	assert.Equal(t, "daemon-1", c.config.DaemonID)
	assert.True(t, c.cache.DaemonConfig().GetEphemeral(), "the enroll config is what the daemon keeps")
}
