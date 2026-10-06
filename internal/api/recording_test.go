package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"io"
	"net/http/httptest"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/recording"
)

type uploadStream = connect.ClientStreamForClientSimple[nokkuv1.UploadRecordingRequest, nokkuv1.UploadRecordingResponse]

// openUpload starts a recording upload the way nokkud does and sends the
// metadata. Canceling ctx is a daemon that dies.
func openUpload(
	ctx context.Context,
	t *testing.T,
	cfg *config.Config,
	srv *httptest.Server,
	key *ecdsa.PrivateKey,
	token, id string,
) *uploadStream {
	t.Helper()
	ctx, call := connect.NewClientContext(ctx)
	call.RequestHeader().Set("Authorization", "DPoP "+token)
	call.RequestHeader().Set("DPoP",
		dpopProof(t, cfg, key, nokkuv1connect.DaemonControlServiceUploadRecordingProcedure, token))
	stream, err := nokkuv1connect.NewDaemonControlServiceClient(srv.Client(), srv.URL).UploadRecording(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&nokkuv1.UploadRecordingRequest{Msg: &nokkuv1.UploadRecordingRequest_Meta{
		Meta: &nokkuv1.RecordingMeta{RecordingId: &id, Username: new("root")},
	}}))
	return stream
}

func sendChunk(stream *uploadStream, chunk []byte) error {
	return stream.Send(&nokkuv1.UploadRecordingRequest{Msg: &nokkuv1.UploadRecordingRequest_Chunk{Chunk: chunk}})
}

// storedBytes is how much of a recording can be read back from storage.
func storedBytes(t *testing.T, cfg *config.Config, id string) int64 {
	t.Helper()
	rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.NoError(t, err)
	r, err := cfg.Record.OpenReader(t.Context(), rec)
	if err != nil {
		return 0
	}
	defer func() { _ = r.Close() }()
	n, _ := io.Copy(io.Discard, r)
	return n
}

// An upload ends at the limit, whatever the daemon sends. What arrived is
// kept and the daemon is told not to try again.
func TestUploadRecordingEndsAtTheLimit(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	id := uuid.NewV7().String()

	stream := openUpload(t.Context(), t, cfg, srv, key, enrolled.GetAccessToken(), id)
	chunk := make([]byte, 1<<20)
	for range maxUploadBytes/len(chunk) + 8 {
		if sendChunk(stream, chunk) != nil {
			break
		}
	}
	_, err := stream.CloseAndReceive()
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "an oversized upload, got %v", err)

	rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.NoError(t, err)
	assert.EqualValues(t, maxUploadBytes, rec.SizeBytes)
	assert.False(t, rec.Complete, "a cut recording is not a complete one")
	assert.NotNil(t, rec.EndedAt)
	assert.EqualValues(t, maxUploadBytes, storedBytes(t, cfg, id), "what arrived before the limit is kept")
}

// A daemon that dies in the middle leaves what it sent so far.
func TestUploadRecordingKeepsWhatADeadDaemonSent(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	id := uuid.NewV7().String()

	ctx, die := context.WithCancel(t.Context())
	stream := openUpload(ctx, t, cfg, srv, key, enrolled.GetAccessToken(), id)
	const sent = 3 * (32 << 10)
	for range 3 {
		require.NoError(t, sendChunk(stream, make([]byte, 32<<10)))
	}
	// The row shows up once the first chunk went through the handler.
	require.Eventually(t, func() bool {
		_, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
		return err == nil
	}, 5*time.Second, 20*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	die()

	require.Eventually(t, func() bool {
		rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
		return err == nil && rec.EndedAt != nil
	}, 5*time.Second, 20*time.Millisecond, "the recording was never closed")
	rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.NoError(t, err)
	assert.EqualValues(t, sent, rec.SizeBytes)
	assert.False(t, rec.Complete)
	assert.EqualValues(t, sent, storedBytes(t, cfg, id))

	// Back up, the daemon sends its whole file and that replaces the part.
	var whole bytes.Buffer
	zw := gzip.NewWriter(&whole)
	_, err = zw.Write([]byte(`{"version":3,"term":{"cols":80,"rows":24}}` + "\n" + `[0.1,"o","done\r\n"]` + "\n"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	stream = openUpload(t.Context(), t, cfg, srv, key, enrolled.GetAccessToken(), id)
	require.NoError(t, sendChunk(stream, whole.Bytes()))
	require.NoError(t, stream.Send(&nokkuv1.UploadRecordingRequest{
		Msg: &nokkuv1.UploadRecordingRequest_Final{Final: &nokkuv1.RecordingFinal{}},
	}))
	_, err = stream.CloseAndReceive()
	require.NoError(t, err)
	rec, err = cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.NoError(t, err)
	assert.True(t, rec.Complete)
	assert.EqualValues(t, whole.Len(), rec.SizeBytes)
	assert.EqualValues(t, whole.Len(), storedBytes(t, cfg, id))
}

// cappedStorage is the SaaS storage cap, a self-hosted instance has none.
type cappedStorage struct{ recording.Limits }

func (cappedStorage) RecordingStorageBytes(context.Context, string) (int64, error) {
	return 10 << 20, nil
}

// An upload over the cap pushes out old recordings, audited, and never a
// recent one.
func TestRecordingEviction(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	_, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	daemonID := enrolled.GetId()

	// Two stored recordings and the upload are over the cap by more than one
	// of them.
	const size = 6 << 20
	seed := func(stored bool) string {
		id := uuid.NewV7().String()
		_, err := cfg.Conn.Sys().CreateRecording(t.Context(), &db.CreateRecordingParams{
			ID:          id,
			WorkspaceID: workspaceID,
			DaemonID:    daemonID,
			Username:    "root",
			Key:         recording.NewKey(),
		})
		require.NoError(t, err)
		if stored {
			_, err = cfg.Conn.Sys().SetRecordingComplete(
				t.Context(),
				&db.SetRecordingCompleteParams{ID: id, SizeBytes: size, Complete: true},
			)
			require.NoError(t, err)
		}
		return id
	}
	old, recent, upload := seed(true), seed(true), seed(false)

	// Only the owner role may rewrite a start time.
	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	defer func() { _ = owner.Close(t.Context()) }()
	_, err = owner.Exec(t.Context(), "UPDATE recordings SET started_at = NOW() - INTERVAL '2 days' WHERE id = $1", old)
	require.NoError(t, err)

	ctx := actor.ContextWithPrincipal(
		actor.AnnotateTenant(t.Context(), workspaceID),
		actor.Principal{ID: daemonID, Kind: actor.KindDaemon, WorkspaceID: workspaceID},
	)
	records := recording.New(t.Context(), cfg.Conn, cfg.Storage, cappedStorage{cfg.Entitlements}, cfg.Audit)
	require.NoError(t, records.EvictForBytes(ctx, workspaceID, upload, size))

	_, err = cfg.Conn.Sys().GetRecording(t.Context(), old)
	require.ErrorIs(t, err, pgx.ErrNoRows, "the old recording makes room")
	_, err = cfg.Conn.Sys().GetRecording(t.Context(), recent)
	require.NoError(t, err, "a recording from today stays, even over the cap")

	events, err := cfg.Conn.Sys().ListAuditLogs(t.Context(), &db.ListAuditLogsParams{
		WorkspaceID: &workspaceID,
		Actions:     []string{"RecordingEvicted"},
		Limit:       10,
	})
	require.NoError(t, err)
	require.Len(t, events, 1, "every eviction is audited")
	assert.Equal(t, old, events[0].Target)
	assert.Contains(t, string(events[0].Details), upload, "the event names the upload that needed the room")
}
