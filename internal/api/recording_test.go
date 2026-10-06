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

// uploadMiB sends a recording of that many MiB and returns the answer the
// daemon got. No final message, so nothing is scrubbed.
func uploadMiB(
	t *testing.T,
	cfg *config.Config,
	srv *httptest.Server,
	key *ecdsa.PrivateKey,
	token, id string,
	mib int,
) error {
	t.Helper()
	stream := openUpload(t.Context(), t, cfg, srv, key, token, id)
	chunk := make([]byte, 1<<20)
	for range mib {
		if sendChunk(stream, chunk) != nil {
			break
		}
	}
	_, err := stream.CloseAndReceive()
	return err
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

	err := uploadMiB(t, cfg, srv, key, enrolled.GetAccessToken(), id, maxUploadBytes>>20+8)
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

// cappedStorage is the storage cap of a hosted plan, a self-hosted instance
// has none.
type cappedStorage struct{ recording.Limits }

const testStorageCap = 10 << 20

func (cappedStorage) RecordingStorageBytes(context.Context, string) (int64, error) {
	return testStorageCap, nil
}

// capStorage runs the test server with that cap.
func capStorage(t *testing.T, cfg *config.Config) {
	t.Helper()
	uncapped := cfg.Record
	cfg.Record = recording.New(t.Context(), cfg.Conn, cfg.Storage, cappedStorage{cfg.Entitlements}, cfg.Audit)
	t.Cleanup(func() { cfg.Record = uncapped })
}

// backdate makes a recording two days old. Only the owner role may rewrite
// a start time.
func backdate(t *testing.T, id string) {
	t.Helper()
	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	defer func() { _ = owner.Close(t.Context()) }()
	_, err = owner.Exec(t.Context(), "UPDATE recordings SET started_at = NOW() - INTERVAL '2 days' WHERE id = $1", id)
	require.NoError(t, err)
}

// Over the cap an upload pushes out old recordings, audited, and never one
// from the last day. When that is not enough the workspace is full: the
// upload is cut, the next one is refused, and both get in once there is room.
func TestRecordingStorageCap(t *testing.T) {
	cfg, srv := newTestAPI(t)
	capStorage(t, cfg)
	workspaceID := seedWorkspace(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	upload := func(id string, mib int) error {
		return uploadMiB(t, cfg, srv, key, enrolled.GetAccessToken(), id, mib)
	}
	stored := func(id string) (*db.Recording, error) {
		return cfg.Conn.Sys().GetRecording(t.Context(), id)
	}
	old, recent, cut, refused := uuid.NewV7().
		String(),
		uuid.NewV7().
			String(),
		uuid.NewV7().
			String(),
		uuid.NewV7().
			String()

	require.NoError(t, upload(old, 6))
	backdate(t, old)
	require.NoError(t, upload(recent, 6), "an old recording is in the way, not a reason to refuse")
	_, err := stored(old)
	require.ErrorIs(t, err, pgx.ErrNoRows, "the old recording makes room")
	events, err := cfg.Conn.Sys().ListAuditLogs(t.Context(), &db.ListAuditLogsParams{
		WorkspaceID: &workspaceID,
		Actions:     []string{"RecordingEvicted"},
		Limit:       10,
	})
	require.NoError(t, err)
	require.Len(t, events, 1, "every eviction is audited")
	assert.Equal(t, old, events[0].Target)
	assert.Contains(t, string(events[0].Details), recent, "the event names the upload that needed the room")

	// Nothing left to evict: the next upload fills the cap and ends there.
	err = upload(cut, 6)
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err), "an upload past the cap, got %v", err)
	rec, err := stored(cut)
	require.NoError(t, err)
	assert.False(t, rec.Complete)
	assert.EqualValues(t, 5<<20, rec.SizeBytes, "the upload ends where the cap is reached")
	assert.EqualValues(t, 5<<20, storedBytes(t, cfg, cut), "and what arrived is kept")
	_, err = stored(recent)
	require.NoError(t, err, "a recording from today stays")

	err = upload(refused, 1)
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err), "an upload into a full workspace, got %v", err)
	_, err = stored(refused)
	require.ErrorIs(t, err, pgx.ErrNoRows, "a refused upload leaves no recording behind")

	// A day later there is room again, and the daemon's next try gets through.
	backdate(t, recent)
	require.NoError(t, upload(cut, 6))
	rec, err = stored(cut)
	require.NoError(t, err)
	assert.EqualValues(t, 6<<20, rec.SizeBytes)
	assert.EqualValues(t, 6<<20, storedBytes(t, cfg, cut), "the whole file replaced the part")
}

// Uploads that run side by side fill the cap together. Without that a
// daemon could store the cap once per stream.
func TestRecordingUploadsShareTheCap(t *testing.T) {
	cfg, srv := newTestAPI(t)
	capStorage(t, cfg)
	workspaceID := seedWorkspace(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	first, second := uuid.NewV7().String(), uuid.NewV7().String()

	// The first upload stays open with most of the cap taken.
	open := openUpload(t.Context(), t, cfg, srv, key, enrolled.GetAccessToken(), first)
	for range 7 {
		require.NoError(t, sendChunk(open, make([]byte, 1<<20)))
	}
	require.Eventually(t, func() bool {
		rec, err := cfg.Conn.Sys().GetRecording(t.Context(), first)
		return err == nil && rec.SizeBytes >= 6<<20
	}, 5*time.Second, 20*time.Millisecond, "an upload in progress is not counted")

	err := uploadMiB(t, cfg, srv, key, enrolled.GetAccessToken(), second, 8)
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err), "a second stream past the cap, got %v", err)
	rec, err := cfg.Conn.Sys().GetRecording(t.Context(), second)
	require.NoError(t, err)
	// Each stream is checked once per interval, so it can be that much over.
	assert.LessOrEqual(t, rec.SizeBytes, int64(testStorageCap-6<<20+quotaCheckInterval),
		"the second stream took more than what was left")

	_, err = open.CloseAndReceive()
	require.NoError(t, err)
}
