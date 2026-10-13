//go:build integration

package api_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/recording"
	"github.com/nokku-sh/nokku/core/internal/storage"
)

type uploadStream = connect.ClientStreamForClientSimple[nokkuv1.UploadRecordingRequest, nokkuv1.UploadRecordingResponse]

// openUpload starts an upload the way nokkud does. Canceling ctx is a daemon that dies.
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

// uploadMiB returns the answer the daemon got. Zeros are no gzip stream, so the scrub gives up on them.
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

// An upload ends at the limit. What arrived is kept and the daemon is told not to try again.
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

// The part a dead daemon left is scrubbed, it may be all there ever is. So is the whole file that replaces it.
func TestCutRecordingIsScrubbed(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	id := uuid.NewV7().String()
	const cast = `{"version":3,"term":{"cols":80,"rows":24}}` + "\n" +
		`[0.1,"o","export DB_PASSWORD=VhT9xNq2mLb4Zw\r\n"]` + "\n"
	stored := func() string {
		rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
		if err != nil {
			return ""
		}
		r, err := cfg.Record.OpenReader(t.Context(), rec)
		if err != nil {
			return ""
		}
		defer func() { _ = r.Close() }()
		gz, err := gzip.NewReader(r)
		if err != nil {
			return ""
		}
		// A cut stream still gives what it holds.
		got, _ := io.ReadAll(gz)
		return string(got)
	}

	// Flushed and never closed, like a stream that stops with its host.
	var part bytes.Buffer
	zw := gzip.NewWriter(&part)
	_, err := zw.Write([]byte(cast))
	require.NoError(t, err)
	require.NoError(t, zw.Flush())
	ctx, die := context.WithCancel(t.Context())
	stream := openUpload(ctx, t, cfg, srv, key, enrolled.GetAccessToken(), id)
	require.NoError(t, sendChunk(stream, part.Bytes()))
	require.Eventually(t, func() bool {
		rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
		return err == nil && rec.SizeBytes == 0
	}, 5*time.Second, 20*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	die()

	require.Eventually(t, func() bool {
		return strings.Contains(stored(), "DB_PASSWORD=<redacted>")
	}, 10*time.Second, 20*time.Millisecond, "the part was not scrubbed")
	assert.NotContains(t, stored(), "VhT9xNq2mLb4Zw")
	rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.NoError(t, err)
	assert.False(t, rec.Complete, "the scrub made the cut recording a whole one")

	var whole bytes.Buffer
	zw = gzip.NewWriter(&whole)
	_, err = zw.Write([]byte(cast + `[0.2,"o","done\r\n"]` + "\n"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	stream = openUpload(t.Context(), t, cfg, srv, key, enrolled.GetAccessToken(), id)
	require.NoError(t, sendChunk(stream, whole.Bytes()))
	require.NoError(t, stream.Send(&nokkuv1.UploadRecordingRequest{
		Msg: &nokkuv1.UploadRecordingRequest_Final{Final: &nokkuv1.RecordingFinal{}},
	}))
	_, err = stream.CloseAndReceive()
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		got := stored()
		return strings.Contains(got, "done") && strings.Contains(got, "DB_PASSWORD=<redacted>")
	}, 10*time.Second, 20*time.Millisecond, "the whole file did not replace the part, or was not scrubbed")
	assert.NotContains(t, stored(), "VhT9xNq2mLb4Zw")
}

// A late upload keeps the time it began. A start from a wrong clock counts as now, or retention would take it at once.
func TestLateUploadKeepsItsStartTime(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	// The daemon has been around for two days.
	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	defer func() { _ = owner.Close(t.Context()) }()
	_, err = owner.Exec(t.Context(),
		"UPDATE daemons SET created_at = NOW() - INTERVAL '2 days' WHERE id = $1", enrolled.GetId())
	require.NoError(t, err)

	startOf := func(named *timestamppb.Timestamp) time.Time {
		id := uuid.NewV7().String()
		ctx, call := connect.NewClientContext(t.Context())
		call.RequestHeader().Set("Authorization", "DPoP "+enrolled.GetAccessToken())
		call.RequestHeader().Set("DPoP", dpopProof(
			t, cfg, key, nokkuv1connect.DaemonControlServiceUploadRecordingProcedure, enrolled.GetAccessToken(),
		))
		stream, err := nokkuv1connect.NewDaemonControlServiceClient(srv.Client(), srv.URL).UploadRecording(ctx)
		require.NoError(t, err)
		require.NoError(t, stream.Send(&nokkuv1.UploadRecordingRequest{Msg: &nokkuv1.UploadRecordingRequest_Meta{
			Meta: &nokkuv1.RecordingMeta{RecordingId: &id, Username: new("root"), StartedAt: named},
		}}))
		_, err = stream.CloseAndReceive()
		require.NoError(t, err)
		rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
		require.NoError(t, err)
		return rec.StartedAt
	}

	began := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	assert.WithinDuration(t, began, startOf(timestamppb.New(began)), time.Second, "a late upload lost its start")
	assert.WithinDuration(t, time.Now(), startOf(nil), time.Minute, "an upload that names no start")
	assert.WithinDuration(t, time.Now(), startOf(timestamppb.New(time.Now().Add(time.Hour))), time.Minute,
		"a start in the future")
	assert.WithinDuration(t, time.Now(), startOf(timestamppb.New(time.Now().AddDate(0, 0, -5))), time.Minute,
		"a start before the daemon enrolled")
	assert.WithinDuration(t, time.Now(), startOf(timestamppb.New(time.Unix(0, 0))), time.Minute,
		"a start from a clock at zero")
}

// The same when storage cannot even open the object. The row exists by then, and it used to stay open.
func TestUploadRecordingIsClosedWhenStorageCannotOpen(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	id := uuid.NewV7().String()

	// A file where the workspace's directory belongs, before the upload starts.
	dir := filepath.Join(os.Getenv("NOKKU_LOCAL_STORAGE_PATH"), filepath.Dir(storage.RecordingPath(workspaceID, id)))
	require.NoError(t, os.RemoveAll(dir))
	require.NoError(t, os.MkdirAll(filepath.Dir(dir), 0o700))
	require.NoError(t, os.WriteFile(dir, nil, 0o600))
	t.Cleanup(func() { _ = os.Remove(dir) })

	stream := openUpload(t.Context(), t, cfg, srv, key, enrolled.GetAccessToken(), id)
	_, err := stream.CloseAndReceive()
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err), "an upload storage could not open, got %v", err)
	rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.NoError(t, err)
	assert.NotNil(t, rec.EndedAt, "the recording stayed open")
	assert.False(t, rec.Complete)
	assert.Zero(t, rec.SizeBytes, "nothing was stored")
}

// When storage fails the recording is closed with nothing stored. Left open it would count as a live session.
func TestUploadRecordingIsClosedWhenStorageFails(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	id := uuid.NewV7().String()

	stream := openUpload(t.Context(), t, cfg, srv, key, enrolled.GetAccessToken(), id)
	require.NoError(t, sendChunk(stream, make([]byte, 32<<10)))
	// The object is written next to where it ends up. Without that directory the commit fails.
	dir := filepath.Join(os.Getenv("NOKKU_LOCAL_STORAGE_PATH"), filepath.Dir(storage.RecordingPath(workspaceID, id)))
	require.Eventually(t, func() bool {
		_, err := os.Stat(dir)
		return err == nil
	}, 5*time.Second, 20*time.Millisecond, "the upload never opened its object")
	// The upload keeps writing while the directory goes, so this may need another go.
	require.Eventually(t, func() bool { return os.RemoveAll(dir) == nil },
		5*time.Second, 20*time.Millisecond, "the storage directory would not go")
	require.NoError(t, os.WriteFile(dir, nil, 0o600))
	t.Cleanup(func() { _ = os.Remove(dir) })

	_, err := stream.CloseAndReceive()
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err), "an upload storage could not keep, got %v", err)
	rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.NoError(t, err)
	assert.NotNil(t, rec.EndedAt, "the recording stayed open")
	assert.False(t, rec.Complete)
	assert.Zero(t, rec.SizeBytes, "nothing was stored")
}

// cappedStorage is the storage cap of a hosted plan, a self-hosted instance has none.
type cappedStorage struct{ recording.Limits }

const testStorageCap = 10 << 20

func (cappedStorage) RecordingStorageBytes(context.Context, string) (int64, error) {
	return testStorageCap, nil
}

// capStorage runs the test server with that cap. Recordings of earlier tests would fill it, so they go first.
func capStorage(t *testing.T, cfg *config.Config) {
	t.Helper()
	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	_, err = owner.Exec(t.Context(), "DELETE FROM recordings")
	require.NoError(t, err)
	require.NoError(t, owner.Close(t.Context()))
	uncapped := cfg.Record
	cfg.Record = recording.New(t.Context(), cfg.Conn, cfg.Storage, cappedStorage{cfg.Entitlements}, cfg.Audit)
	t.Cleanup(func() { cfg.Record = uncapped })
}

// backdate makes a recording that many days old. Only the owner role may rewrite a start time.
func backdate(t *testing.T, id string, days int) {
	t.Helper()
	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	defer func() { _ = owner.Close(t.Context()) }()
	_, err = owner.Exec(t.Context(),
		"UPDATE recordings SET started_at = NOW() - make_interval(days => $2) WHERE id = $1", id, days)
	require.NoError(t, err)
}

// Over the cap an upload evicts old recordings, never one from the last day. A full workspace cuts and refuses.
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
	backdate(t, old, 2)
	require.NoError(t, upload(recent, 6), "an old recording is in the way, not a reason to refuse")
	_, err := stored(old)
	require.ErrorIs(t, err, pgx.ErrNoRows, "the old recording makes room")
	var events []*db.ListAuditLogsRow
	inWorkspace(t, cfg, workspaceID, func(q *db.Queries) (err error) {
		// Other tests evict in the same workspace, in any order.
		events, err = q.ListAuditLogs(t.Context(), &db.ListAuditLogsParams{
			Actions: []string{"RecordingEvicted"},
			Target:  &old,
			Limit:   10,
		})
		return err
	})
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
	backdate(t, recent, 2)
	require.NoError(t, upload(cut, 6))
	rec, err = stored(cut)
	require.NoError(t, err)
	assert.EqualValues(t, 6<<20, rec.SizeBytes)
	assert.EqualValues(t, 6<<20, storedBytes(t, cfg, cut), "the whole file replaced the part")
}

// Eviction takes the oldest recordings and stops as soon as the upload fits.
func TestRecordingEvictionTakesNoMoreThanNeeded(t *testing.T) {
	cfg, srv := newTestAPI(t)
	capStorage(t, cfg)
	workspaceID := seedWorkspace(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	upload := func(mib int) string {
		id := uuid.NewV7().String()
		require.NoError(t, uploadMiB(t, cfg, srv, key, enrolled.GetAccessToken(), id, mib))
		return id
	}

	oldest, older, old := upload(3), upload(3), upload(3)
	backdate(t, oldest, 4)
	backdate(t, older, 3)
	backdate(t, old, 2)
	upload(3)

	_, err := cfg.Conn.Sys().GetRecording(t.Context(), oldest)
	require.ErrorIs(t, err, pgx.ErrNoRows, "the oldest recording makes room")
	for _, id := range []string{older, old} {
		_, err = cfg.Conn.Sys().GetRecording(t.Context(), id)
		require.NoError(t, err, "one recording was enough, a second one went too")
	}
}

// Uploads side by side fill the cap together, or a daemon could store the cap once per stream.
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

// A recording belongs to the daemon that started it. The answer tells another daemon to drop its file, a retry
// would block every later upload of that host.
func TestUploadForAnotherDaemonsRecordingIsRefused(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	otherKey, other := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	id := uuid.NewV7().String()
	require.NoError(t, uploadMiB(t, cfg, srv, key, enrolled.GetAccessToken(), id, 1))

	err := uploadMiB(t, cfg, srv, otherKey, other.GetAccessToken(), id, 1)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "got %v", err)
	assert.EqualValues(t, 1<<20, storedBytes(t, cfg, id), "the refused upload touched what was stored")
}

// A retry that is cut earlier than the upload before it must not replace the longer part.
func TestShorterRetryKeepsTheLongerUpload(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	id := uuid.NewV7().String()
	// cut sends chunks and dies, then waits until the handler closed the recording again.
	cut := func(chunks int) *db.Recording {
		var before time.Time
		if rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id); err == nil && rec.EndedAt != nil {
			before = *rec.EndedAt
		}
		ctx, die := context.WithCancel(t.Context())
		stream := openUpload(ctx, t, cfg, srv, key, enrolled.GetAccessToken(), id)
		for range chunks {
			require.NoError(t, sendChunk(stream, make([]byte, 32<<10)))
		}
		time.Sleep(300 * time.Millisecond)
		die()
		var rec *db.Recording
		require.Eventually(t, func() bool {
			var err error
			rec, err = cfg.Conn.Sys().GetRecording(t.Context(), id)
			return err == nil && rec.EndedAt != nil && rec.EndedAt.After(before)
		}, 5*time.Second, 20*time.Millisecond, "the recording was never closed")
		return rec
	}

	const long = 3 * (32 << 10)
	assert.EqualValues(t, long, cut(3).SizeBytes)

	rec := cut(1)
	assert.EqualValues(t, long, rec.SizeBytes, "the shorter retry set the size")
	assert.False(t, rec.Complete)
	assert.EqualValues(t, long, storedBytes(t, cfg, id), "the shorter retry replaced the longer upload")
}
