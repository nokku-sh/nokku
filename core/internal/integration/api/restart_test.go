//go:build integration

package api_test

import (
	"context"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokku/internal/dpop"
	"github.com/nokku-sh/nokku/internal/dpopclient"

	"github.com/nokku-sh/nokku/core/internal/iam"
)

// A restart gives the core a new nonce key. A daemon holding a nonce of the old boot syncs and connects by itself, wired
// the way nokkud wires its client, and people stay signed in.
func TestClientsOutliveACoreRestart(t *testing.T) {
	selfHostedOnly(t, "it dials the real listener, which reads no workspace host")
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	member := seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)

	restarted := *cfg
	var err error
	restarted.IAM, err = iam.New(t.Context(), iam.Deps{Conn: cfg.Conn, Keyset: cfg.Keyset, Audit: cfg.Audit})
	require.NoError(t, err)
	oldNonce := cfg.IAM.DPoP.CurrentNonce()
	require.NotEqual(t, oldNonce, restarted.IAM.DPoP.CurrentNonce(), "the nonce key outlived the boot")
	client, base, _ := startSecondCore(t, &restarted)

	proofer, err := dpop.NewProofer(key)
	require.NoError(t, err)
	token := enrolled.GetAccessToken()
	daemon := dpopclient.New(
		proofer,
		client,
		func() string { return token },
		dpopclient.Options{BaseURL: testWorkspace.BaseURL},
	)
	ctl := nokkuv1connect.NewDaemonControlServiceClient(
		connect.NewClient(connecthttp.NewTransport(client, base), daemon.Intercept))

	daemon.Learn(oldNonce)
	sync, err := ctl.SyncDaemon(t.Context(), &nokkuv1.SyncDaemonRequest{})
	require.NoError(t, err, "a sync with a nonce of the old boot did not retry by itself")
	assert.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED, sync.GetStatus())

	// A stream is signed once, so the first dial fails and tells the next one the nonce.
	daemon.Learn(oldNonce)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	heartbeat := &nokkuv1.ConnectRequest{
		Msg: &nokkuv1.ConnectRequest_Heartbeat{Heartbeat: &nokkuv1.Heartbeat{}},
	}
	refused, err := ctl.Connect(ctx)
	require.NoError(t, err)
	_ = refused.Send(heartbeat)
	_, err = refused.Receive()
	require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "got %v", err)

	dialed, err := ctl.Connect(ctx)
	require.NoError(t, err)
	require.NoError(t, dialed.Send(heartbeat))
	require.Eventually(t, func() bool { return restarted.Pool.IsConnected(enrolled.GetId()) },
		5*time.Second, 20*time.Millisecond, "the daemon's second dial did not connect")

	// An upload is a stream too. Its first try fails the same way, and the daemon's next try has the nonce.
	id := uuid.NewV7().String()
	upload := func() error {
		stream, err := ctl.UploadRecording(t.Context())
		require.NoError(t, err)
		_ = stream.Send(&nokkuv1.UploadRecordingRequest{Msg: &nokkuv1.UploadRecordingRequest_Meta{
			Meta: &nokkuv1.RecordingMeta{RecordingId: &id, Username: new("root")},
		}})
		_, err = stream.CloseAndReceive()
		return err
	}
	daemon.Learn(oldNonce)
	require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(upload()), "the upload had no old nonce to fail on")
	require.NoError(t, upload(), "the next try of an upload did not learn the nonce")

	signedIn := nokkuv1connect.NewCertificateServiceClient(
		connect.NewClient(connecthttp.NewTransport(client, base), header("Authorization", "Bearer "+member)))
	_, err = signedIn.GetCertificateAuthority(t.Context(), &nokkuv1.GetCertificateAuthorityRequest{})
	assert.NoError(t, err, "a restart signed someone out")
}
