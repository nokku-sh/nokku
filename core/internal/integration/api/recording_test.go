//go:build integration

package api_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/app"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/recording"
	"github.com/nokku-sh/nokku/core/internal/storage"
)

const testStorageCap = 10 << 20

type uploadStream = nokkuv1connect.DaemonControlServiceUploadRecordingClientStream

// cappedStorage is a hosted plan's cap, a self-hosted instance has none.
type cappedStorage struct{ recording.Limits }

// openUpload starts an upload like nokkud. Canceling ctx is a daemon dying.
func openUpload(
	ctx context.Context,
	t *testing.T,
	cfg *app.Config,
	srv *httptest.Server,
	key *ecdsa.PrivateKey,
	token, id string,
) uploadStream {
	t.Helper()
	ctx, call := connect.NewClientContext(ctx)
	call.RequestHeader().Set("Authorization", "DPoP "+token)
	call.RequestHeader().Set("DPoP",
		dpopProof(t, cfg, key, nokkuv1connect.DaemonControlServiceUploadRecordingProcedure, token))
	stream, err := nokkuv1connect.NewDaemonControlServiceClient(clientOn(srv)).
		UploadRecording(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&nokkuv1.UploadRecordingRequest{Msg: &nokkuv1.UploadRecordingRequest_Meta{
		Meta: &nokkuv1.RecordingMeta{RecordingId: &id, Username: new("root")},
	}}))
	return stream
}

func sendChunk(stream uploadStream, chunk []byte) error {
	return stream.Send(&nokkuv1.UploadRecordingRequest{Msg: &nokkuv1.UploadRecordingRequest_Chunk{Chunk: chunk}})
}

// uploadMiB returns the answer the daemon got.
func uploadMiB(
	t *testing.T,
	cfg *app.Config,
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
func storedBytes(t *testing.T, cfg *app.Config, id string) int64 {
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

// What arrived before the limit is kept, the daemon is told not to retry.
func TestUploadRecordingEndsAtTheLimit(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	id := uuid.NewV7().String()

	err := uploadMiB(t, cfg, srv, key, enrolled.GetAccessToken(), id, maxUploadBytes>>20+8)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "an oversized upload, got %v", err)

	rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.NoError(t, err)
	assert.EqualValues(t, maxUploadBytes, rec.SizeBytes)
	assert.False(t, rec.Complete, "a cut recording is not a complete one")
	assert.EqualValues(t, maxUploadBytes, storedBytes(t, cfg, id), "what arrived before the limit is kept")
}

func TestUploadRecordingKeepsWhatADeadDaemonSent(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	id := uuid.NewV7().String()

	whole := randomBytes(4 * pendingChunk)
	const sent = 3 * pendingChunk
	ctx, die := context.WithCancel(t.Context())
	stream := openUpload(ctx, t, cfg, srv, key, enrolled.GetAccessToken(), id)
	sendLive(t, stream, whole[:sent])
	waitHandled(t, cfg, id)
	die()

	rec := waitStored(t, cfg, id, sent)
	assert.False(t, rec.Complete)
	assert.Nil(t, rec.EndedAt, "only the daemon can say its session ended")
	assert.EqualValues(t, sent, storedBytes(t, cfg, id))

	// Back up, the daemon sends its whole file and that replaces the part.
	require.NoError(t, uploadFile(t, cfg, srv, key, enrolled.GetAccessToken(), id, whole, ""))
	rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.NoError(t, err)
	assert.True(t, rec.Complete)
	assert.EqualValues(t, len(whole), rec.SizeBytes)
	assert.EqualValues(t, len(whole), storedBytes(t, cfg, id))
}

// A dead daemon's part may be all there is, only the whole file replaces it.
func TestCutRecordingIsKept(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
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
		return strings.Contains(stored(), "DB_PASSWORD")
	}, 10*time.Second, 20*time.Millisecond, "the part was not kept")
	rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.NoError(t, err)
	assert.False(t, rec.Complete, "a cut recording counts as whole")

	var whole bytes.Buffer
	zw = gzip.NewWriter(&whole)
	_, err = zw.Write([]byte(cast + `[0.2,"o","done\r\n"]` + "\n"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	stream = openUpload(t.Context(), t, cfg, srv, key, enrolled.GetAccessToken(), id)
	require.NoError(t, sendChunk(stream, whole.Bytes()))
	require.NoError(t, stream.Send(finalOf(whole.Len(), "")))
	_, err = stream.CloseAndReceive()
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return strings.Contains(stored(), "done")
	}, 10*time.Second, 20*time.Millisecond, "the whole file did not replace the part")
}

// A start from a wrong clock counts as now, or retention would take it at once.
func TestLateUploadKeepsItsStartTime(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
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
		stream, err := nokkuv1connect.NewDaemonControlServiceClient(clientOn(srv)).
			UploadRecording(ctx)
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

// The end counts, not when the file arrived. A wrong clock counts as now.
func TestLateUploadKeepsItsEndTime(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	defer func() { _ = owner.Close(t.Context()) }()
	_, err = owner.Exec(t.Context(),
		"UPDATE daemons SET created_at = NOW() - INTERVAL '2 days' WHERE id = $1", enrolled.GetId())
	require.NoError(t, err)

	began := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	endOf := func(named *timestamppb.Timestamp) time.Time {
		id := uuid.NewV7().String()
		ctx, call := connect.NewClientContext(t.Context())
		call.RequestHeader().Set("Authorization", "DPoP "+enrolled.GetAccessToken())
		call.RequestHeader().Set("DPoP", dpopProof(
			t, cfg, key, nokkuv1connect.DaemonControlServiceUploadRecordingProcedure, enrolled.GetAccessToken(),
		))
		stream, err := nokkuv1connect.NewDaemonControlServiceClient(clientOn(srv)).
			UploadRecording(ctx)
		require.NoError(t, err)
		require.NoError(t, stream.Send(&nokkuv1.UploadRecordingRequest{Msg: &nokkuv1.UploadRecordingRequest_Meta{
			Meta: &nokkuv1.RecordingMeta{RecordingId: &id, Username: new("root"), StartedAt: timestamppb.New(began)},
		}}))
		require.NoError(t, sendChunk(stream, []byte("x")))
		require.NoError(t, stream.Send(&nokkuv1.UploadRecordingRequest{Msg: &nokkuv1.UploadRecordingRequest_Final{
			Final: &nokkuv1.RecordingFinal{SizeBytes: new(int64(1)), EndedAt: named},
		}}))
		_, err = stream.CloseAndReceive()
		require.NoError(t, err)
		rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
		require.NoError(t, err)
		require.NotNil(t, rec.EndedAt, "the last message of a session left it open")
		return *rec.EndedAt
	}

	ended := began.Add(time.Hour)
	assert.WithinDuration(t, ended, endOf(timestamppb.New(ended)), time.Second, "a late upload lost its end")
	assert.WithinDuration(t, time.Now(), endOf(nil), time.Minute, "an upload that names no end")
	assert.WithinDuration(t, time.Now(), endOf(timestamppb.New(time.Now().Add(time.Hour))), time.Minute,
		"an end in the future")
	assert.WithinDuration(t, time.Now(), endOf(timestamppb.New(began.Add(-time.Hour))), time.Minute,
		"an end before the start")
}

func TestStorageThatCannotOpenLeavesTheRowToTheNextTry(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	id := uuid.NewV7().String()

	// A file where the workspace's directory belongs, before the upload starts.
	dir := filepath.Join(storageDir, filepath.Dir(storage.RecordingPath(workspaceID, id)))
	require.NoError(t, os.RemoveAll(dir))
	require.NoError(t, os.MkdirAll(filepath.Dir(dir), 0o700))
	require.NoError(t, os.WriteFile(dir, nil, 0o600))
	t.Cleanup(func() { _ = os.Remove(dir) })

	stream := openUpload(t.Context(), t, cfg, srv, key, enrolled.GetAccessToken(), id)
	_, err := stream.CloseAndReceive()
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err), "an upload storage could not open, got %v", err)
	rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.NoError(t, err)
	assert.Nil(t, rec.EndedAt, "a failed try says nothing about the session")
	assert.False(t, rec.Complete)
	assert.Zero(t, rec.SizeBytes, "nothing was stored")
}

// A commit that fails stores nothing and tells the daemon to try again.
func TestFailedCommitLeavesTheRowToTheNextTry(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	id := uuid.NewV7().String()

	stream := openUpload(t.Context(), t, cfg, srv, key, enrolled.GetAccessToken(), id)
	require.NoError(t, sendChunk(stream, make([]byte, 32<<10)))
	// The commit fails without the directory the object is written next to.
	dir := filepath.Join(storageDir, filepath.Dir(storage.RecordingPath(workspaceID, id)))
	require.Eventually(t, func() bool {
		_, err := os.Stat(dir)
		return err == nil
	}, 5*time.Second, 20*time.Millisecond, "the upload never opened its object")
	// The upload writes on while the directory goes, so this may take a retry.
	require.Eventually(t, func() bool { return os.RemoveAll(dir) == nil },
		5*time.Second, 20*time.Millisecond, "the storage directory would not go")
	require.NoError(t, os.WriteFile(dir, nil, 0o600))
	t.Cleanup(func() { _ = os.Remove(dir) })

	_, err := stream.CloseAndReceive()
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err), "an upload storage could not keep, got %v", err)
	rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.NoError(t, err)
	assert.Nil(t, rec.EndedAt, "a failed try says nothing about the session")
	assert.Nil(t, rec.ObjectID, "the row names an object that was never stored")
	assert.False(t, rec.Complete)
	assert.Zero(t, rec.SizeBytes, "nothing was stored")
}

// A closing transaction that fails after the commit leaves the object in no
// row, so the delete queue must take it.
func TestFailedCloseQueuesTheStoredObject(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	id := uuid.NewV7().String()

	// Only the owner role may add a trigger.
	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = owner.Close(context.WithoutCancel(t.Context())) })
	fail := "fail_" + strings.ReplaceAll(id, "-", "")
	_, err = owner.Exec(t.Context(), fmt.Sprintf(`
		CREATE FUNCTION %[1]s() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'no close'; END $$;
		CREATE TRIGGER %[1]s BEFORE UPDATE ON recordings FOR EACH ROW WHEN (OLD.id = '%[2]s') EXECUTE FUNCTION %[1]s();`,
		fail, id))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := owner.Exec(context.WithoutCancel(t.Context()),
			fmt.Sprintf("DROP TRIGGER %[1]s ON recordings; DROP FUNCTION %[1]s();", fail))
		assert.NoError(t, err)
	})

	require.NoError(t, cfg.Record.DeleteQueued(t.Context()))
	before := storedObjects(t, workspaceID)
	err = uploadMiB(t, cfg, srv, key, enrolled.GetAccessToken(), id, 1)
	require.Equal(t, connect.CodeInternal, connect.CodeOf(err), "the row closed despite the trigger: %v", err)
	require.Len(t, storedObjects(t, workspaceID), len(before)+1, "the upload stored no object")

	require.NoError(t, cfg.Record.DeleteQueued(t.Context()))
	assert.ElementsMatch(t, before, storedObjects(t, workspaceID), "the stored object is in no row and not queued")
}

func (cappedStorage) RecordingStorageBytes(context.Context, string) (int64, error) {
	return testStorageCap, nil
}

// capStorage caps the server. Earlier recordings would fill it, so they go.
func capStorage(t *testing.T, cfg *app.Config) {
	t.Helper()
	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	_, err = owner.Exec(t.Context(), "DELETE FROM recordings")
	require.NoError(t, err)
	require.NoError(t, owner.Close(t.Context()))
	store, err := storage.New(t.Context())
	require.NoError(t, err)
	uncapped := cfg.Record
	cfg.Record = recording.New(
		t.Context(),
		cfg.Conn,
		cfg.Keyset,
		store,
		cappedStorage{cfg.Entitlements},
		cfg.Audit,
	)
	t.Cleanup(func() { cfg.Record = uncapped })
}

// backdate ages a recording. Only the owner role may rewrite a start time.
func backdate(t *testing.T, id string, days int) {
	t.Helper()
	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	defer func() { _ = owner.Close(t.Context()) }()
	_, err = owner.Exec(t.Context(),
		"UPDATE recordings SET started_at = NOW() - make_interval(days => $2) WHERE id = $1", id, days)
	require.NoError(t, err)
}

// An upload over the cap evicts old recordings, never one from the last day.
func TestRecordingStorageCap(t *testing.T) {
	cfg, srv := newTestAPI(t)
	capStorage(t, cfg)
	workspaceID := testWorkspace.ID
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	upload := func(id string, mib int) error {
		return uploadMiB(t, cfg, srv, key, enrolled.GetAccessToken(), id, mib)
	}
	stored := func(id string) (*db.Recording, error) {
		return cfg.Conn.Sys().GetRecording(t.Context(), id)
	}
	old, recent, next, last, refused := uuid.NewV7().String(), uuid.NewV7().String(), uuid.NewV7().String(),
		uuid.NewV7().String(), uuid.NewV7().String()

	require.NoError(t, upload(old, 6))
	backdate(t, old, 2)
	require.NoError(t, upload(recent, 6), "the cap is asked when an upload starts, this one started under it")
	require.NoError(t, upload(next, 1), "an old recording is in the way, not a reason to refuse")
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
	assert.Contains(t, string(events[0].Details), next, "the event names the upload that needed the room")

	// Over the cap with nothing to evict, the workspace takes no new upload.
	require.NoError(t, upload(last, 6))
	err = upload(refused, 1)
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err), "an upload into a full workspace, got %v", err)
	_, err = stored(refused)
	require.ErrorIs(t, err, pgx.ErrNoRows, "a refused upload leaves no recording behind")
	_, err = stored(recent)
	require.NoError(t, err, "a recording from today stays")

	// A day later there is room again, and the daemon's next try gets through.
	backdate(t, recent, 2)
	require.NoError(t, upload(refused, 1))
	rec, err := stored(refused)
	require.NoError(t, err)
	assert.EqualValues(t, 1<<20, rec.SizeBytes)
	assert.EqualValues(t, 1<<20, storedBytes(t, cfg, refused))
}

// Eviction takes the oldest and stops once the workspace is under the cap.
func TestRecordingEvictionTakesNoMoreThanNeeded(t *testing.T) {
	cfg, srv := newTestAPI(t)
	capStorage(t, cfg)
	workspaceID := testWorkspace.ID
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
	evicted := objectOf(t, cfg, oldest)
	upload(3)
	upload(1)

	_, err := cfg.Conn.Sys().GetRecording(t.Context(), oldest)
	require.ErrorIs(t, err, pgx.ErrNoRows, "the oldest recording makes room")
	for _, id := range []string{older, old} {
		_, err = cfg.Conn.Sys().GetRecording(t.Context(), id)
		require.NoError(t, err, "one recording was enough, a second one went too")
	}
	// capStorage's sweeper may have run already, only the end state is certain.
	require.NoError(t, cfg.Record.DeleteQueued(t.Context()))
	assert.False(t, objectExists(workspaceID, evicted), "the delete queue left the evicted object")
}

// objectPath is where the test server's storage keeps an object.
func objectPath(workspaceID, objectID string) string {
	return filepath.Join(storageDir, filepath.FromSlash(storage.RecordingPath(workspaceID, objectID)))
}

func objectExists(workspaceID, objectID string) bool {
	_, err := os.Stat(objectPath(workspaceID, objectID))
	return err == nil
}

// storedObjects lists what a workspace has committed, whichever row names it.
func storedObjects(t *testing.T, workspaceID string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(objectPath(workspaceID, "any")))
	// The first object makes the directory, tests that break storage drop it.
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	require.NoError(t, err)
	var names []string
	for _, entry := range entries {
		if name, ok := strings.CutSuffix(entry.Name(), ".cast.gz"); ok {
			names = append(names, name)
		}
	}
	return names
}

func objectOf(t *testing.T, cfg *app.Config, id string) string {
	t.Helper()
	rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.NoError(t, err)
	require.NotNil(t, rec.ObjectID, "nothing of the recording is stored")
	return *rec.ObjectID
}

func deleteRecording(t *testing.T, cfg *app.Config, srv *httptest.Server, workspaceID, id string) {
	t.Helper()
	editor := clientOn(srv, header("Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR)))
	_, err := nokkuv1connect.NewRecordingServiceClient(editor).
		DeleteRecording(t.Context(), &nokkuv1.DeleteRecordingRequest{RecordingId: &id})
	require.NoError(t, err)
}

// A playback leaves no other trace, so nothing plays unless the log has it.
func TestPlaybackNeedsItsAuditRow(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	id := uuid.NewV7().String()
	require.NoError(t, uploadMiB(t, cfg, srv, key, enrolled.GetAccessToken(), id, 1))
	viewer := seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER)
	play := func() error {
		ctx, call := connect.NewClientContext(t.Context())
		call.RequestHeader().Set("Authorization", "Bearer "+viewer)
		stream, err := nokkuv1connect.NewRecordingServiceClient(clientOn(srv)).
			GetRecording(ctx, &nokkuv1.GetRecordingRequest{RecordingId: &id})
		if err != nil {
			return err
		}
		defer func() { _ = stream.Close() }()
		_, err = stream.Receive()
		return err
	}

	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	restore := func() {
		_, err := owner.Exec(context.WithoutCancel(t.Context()), "GRANT INSERT ON audit.audit_logs TO nokku_app")
		require.NoError(t, err)
	}
	t.Cleanup(func() { restore(); _ = owner.Close(context.WithoutCancel(t.Context())) })
	_, err = owner.Exec(t.Context(), "REVOKE INSERT ON audit.audit_logs FROM nokku_app")
	require.NoError(t, err)

	require.Error(t, play(), "a recording played with no row in the log")
	restore()
	require.NoError(t, play(), "a recording did not play once the log worked again")
}

// A deleted recording loses its key at once, its object when the queue runs.
func TestDeletedRecordingObjectGoesThroughTheQueue(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	id := uuid.NewV7().String()
	require.NoError(t, uploadMiB(t, cfg, srv, key, enrolled.GetAccessToken(), id, 1))
	object := objectOf(t, cfg, id)
	require.True(t, objectExists(workspaceID, object), "the upload stored nothing")

	deleteRecording(t, cfg, srv, workspaceID, id)
	_, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.ErrorIs(t, err, pgx.ErrNoRows, "the row outlived the delete")
	require.True(t, objectExists(workspaceID, object), "the object went before the delete queue ran")

	require.NoError(t, cfg.Record.DeleteQueued(t.Context()))
	assert.False(t, objectExists(workspaceID, object), "the delete queue left the object")
}

// A deleted id can come back. The queue takes the old object, not the new one.
func TestRecordingMadeAgainKeepsItsNewObject(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	id := uuid.NewV7().String()
	require.NoError(t, uploadMiB(t, cfg, srv, key, enrolled.GetAccessToken(), id, 1))
	first := objectOf(t, cfg, id)

	deleteRecording(t, cfg, srv, workspaceID, id)
	require.NoError(t, uploadMiB(t, cfg, srv, key, enrolled.GetAccessToken(), id, 1))
	second := objectOf(t, cfg, id)
	require.NotEqual(t, first, second, "the recording came back on the object that is queued for deletion")

	require.NoError(t, cfg.Record.DeleteQueued(t.Context()))
	assert.False(t, objectExists(workspaceID, first), "the delete queue left the old object")
	assert.True(t, objectExists(workspaceID, second), "the delete queue took the new object")
	assert.EqualValues(t, 1<<20, storedBytes(t, cfg, id))
}

// The new key can't read a running upload, so the queue takes its object.
func TestUploadOfARecordingMadeAgainLeavesNoObject(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	id := uuid.NewV7().String()

	running := openUpload(t.Context(), t, cfg, srv, key, enrolled.GetAccessToken(), id)
	require.NoError(t, sendChunk(running, make([]byte, 32<<10)))
	require.Eventually(t, func() bool {
		_, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
		return err == nil
	}, 5*time.Second, 20*time.Millisecond, "the upload made no row")

	deleteRecording(t, cfg, srv, workspaceID, id)
	require.NoError(t, uploadMiB(t, cfg, srv, key, enrolled.GetAccessToken(), id, 1))
	second := objectOf(t, cfg, id)
	// Drained first, so only the running upload can add to what is stored.
	require.NoError(t, cfg.Record.DeleteQueued(t.Context()))
	before := storedObjects(t, workspaceID)

	_, err := running.CloseAndReceive()
	require.Error(t, err, "an upload of a row that went was stored")
	require.NoError(t, cfg.Record.DeleteQueued(t.Context()))
	assert.ElementsMatch(t, before, storedObjects(t, workspaceID), "the old upload left an object nothing tracks")
	assert.True(t, objectExists(workspaceID, second), "the old upload took the new object")
	assert.Equal(t, second, objectOf(t, cfg, id), "the old upload moved the row onto an object its key can't read")
	assert.EqualValues(t, 1<<20, storedBytes(t, cfg, id))
	entries, err := os.ReadDir(filepath.Dir(objectPath(workspaceID, second)))
	require.NoError(t, err)
	for _, entry := range entries {
		assert.False(t, strings.HasSuffix(entry.Name(), ".tmp"), "the old upload left %s behind", entry.Name())
	}
}

// An object that won't delete waits with its error, the ones after it still go.
func TestFailedRecordingDeleteHoldsUpNothing(t *testing.T) {
	cfg, _ := newTestAPI(t)
	workspaceID := testWorkspace.ID
	stuck, next := uuid.NewV7().String(), uuid.NewV7().String()
	// A full directory where the object belongs, no delete takes that.
	stuckPath := objectPath(workspaceID, stuck)
	require.NoError(t, os.MkdirAll(filepath.Join(stuckPath, "x"), 0o700))
	require.NoError(t, os.WriteFile(objectPath(workspaceID, next), []byte("x"), 0o600))

	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.WithoutCancel(t.Context())
		_, _ = owner.Exec(ctx, "DELETE FROM recording_deletes WHERE object_id = $1", stuck)
		_ = owner.Close(ctx)
		_ = os.RemoveAll(stuckPath)
	})
	_, err = owner.Exec(t.Context(), `
		INSERT INTO recording_deletes (object_id, workspace_id, next_try_at)
		VALUES ($1, $3, NOW() - INTERVAL '2 minutes'), ($2, $3, NOW() - INTERVAL '1 minute')`,
		stuck, next, workspaceID)
	require.NoError(t, err)

	require.NoError(t, cfg.Record.DeleteQueued(t.Context()), "one failed delete ended the pass")
	assert.False(t, objectExists(workspaceID, next), "the object queued after a failing one stayed")

	var attempts int
	var lastError *string
	var due time.Time
	require.NoError(t, owner.QueryRow(t.Context(),
		"SELECT attempts, last_error, next_try_at FROM recording_deletes WHERE object_id = $1", stuck,
	).Scan(&attempts, &lastError, &due))
	assert.Equal(t, 1, attempts)
	assert.NotEmpty(t, lastError, "the failure left no error on its row")
	assert.True(t, due.After(time.Now()), "the failed delete is due again at once")
}

// Over the limit a daemon hears to retry soon, a session's end frees a slot.
func TestOpenUploadsOfADaemonAreLimited(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	token := enrolled.GetAccessToken()

	ids := make([]string, maxOpenUploads)
	open := make([]uploadStream, maxOpenUploads)
	for i := range open {
		ids[i] = uuid.NewV7().String()
		open[i] = openUpload(t.Context(), t, cfg, srv, key, token, ids[i])
	}
	t.Cleanup(func() {
		for _, stream := range open {
			_, _ = stream.CloseAndReceive()
		}
	})
	require.Eventually(t, func() bool {
		for _, id := range ids {
			if _, err := cfg.Conn.Sys().GetRecording(t.Context(), id); err != nil {
				return false
			}
		}
		return true
	}, 30*time.Second, 50*time.Millisecond, "the open uploads never reached the handler")

	over := uuid.NewV7().String()
	_, err := openUpload(t.Context(), t, cfg, srv, key, token, over).CloseAndReceive()
	assert.Equal(t, connect.CodeUnavailable, connect.CodeOf(err), "an upload over the limit, got %v", err)

	other, otherDaemon := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	_, err = openUpload(t.Context(), t, cfg, srv, other, otherDaemon.GetAccessToken(), uuid.NewV7().String()).
		CloseAndReceive()
	require.NoError(t, err, "the limit of one daemon held up another")

	_, err = open[0].CloseAndReceive()
	require.NoError(t, err)
	_, err = openUpload(t.Context(), t, cfg, srv, key, token, over).CloseAndReceive()
	require.NoError(t, err, "an upload that ended gave its slot back")
}

// The answer tells the other daemon to drop the file, a retry would block it.
func TestUploadForAnotherDaemonsRecordingIsRefused(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	otherKey, other := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	id := uuid.NewV7().String()
	require.NoError(t, uploadMiB(t, cfg, srv, key, enrolled.GetAccessToken(), id, 1))

	err := uploadMiB(t, cfg, srv, otherKey, other.GetAccessToken(), id, 1)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "got %v", err)
	assert.EqualValues(t, 1<<20, storedBytes(t, cfg, id), "the refused upload touched what was stored")
}

func TestShorterRetryKeepsTheLongerUpload(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	id := uuid.NewV7().String()
	// cut ends the stream without its last message, the way a broken one ends.
	cut := func(chunks int) *db.Recording {
		stream := openUpload(t.Context(), t, cfg, srv, key, enrolled.GetAccessToken(), id)
		for range chunks {
			require.NoError(t, sendChunk(stream, make([]byte, 32<<10)))
		}
		_, err := stream.CloseAndReceive()
		require.NoError(t, err)
		rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
		require.NoError(t, err)
		return rec
	}

	const long = 3 * (32 << 10)
	assert.EqualValues(t, long, cut(3).SizeBytes)

	rec := cut(1)
	assert.EqualValues(t, long, rec.SizeBytes, "the shorter retry set the size")
	assert.False(t, rec.Complete)
	assert.EqualValues(t, long, storedBytes(t, cfg, id), "the shorter retry replaced the longer upload")
}
