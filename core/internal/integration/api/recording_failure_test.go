//go:build integration

package api_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/api"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/recording"
)

// The chunk size nokkud reads a recording file in.
const pendingChunk = 32 << 10

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// storedCopy is the recording as storage gives it back, nil when there is no object.
func storedCopy(t *testing.T, cfg *config.Config, id string) []byte {
	t.Helper()
	rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.NoError(t, err)
	r, err := cfg.Record.OpenReader(t.Context(), rec)
	if err != nil {
		return nil
	}
	defer func() { _ = r.Close() }()
	data, err := io.ReadAll(r)
	require.NoError(t, err, "the stored copy does not read back")
	return data
}

// finalOf is the last message nokkud sends for a file of that size.
func finalOf(size int, cutReason string) *nokkuv1.UploadRecordingRequest {
	return &nokkuv1.UploadRecordingRequest{Msg: &nokkuv1.UploadRecordingRequest_Final{
		Final: &nokkuv1.RecordingFinal{SizeBytes: new(int64(size)), CutReason: &cutReason},
	}}
}

// uploadFile sends a file the way nokkud does: meta, 32 KiB chunks and the last message with the file's size.
func uploadFile(
	t *testing.T,
	cfg *config.Config,
	srv *httptest.Server,
	key *ecdsa.PrivateKey,
	token, id string,
	data []byte,
	cutReason string,
) error {
	t.Helper()
	stream := openUpload(t.Context(), t, cfg, srv, key, token, id)
	for chunk := range slices.Chunk(data, pendingChunk) {
		if sendChunk(stream, chunk) != nil {
			break
		}
	}
	_ = stream.Send(finalOf(len(data), cutReason))
	_, err := stream.CloseAndReceive()
	return err
}

// sendLive sends data like a live upload that has not ended yet.
func sendLive(t *testing.T, stream uploadStream, data []byte) {
	t.Helper()
	for chunk := range slices.Chunk(data, pendingChunk) {
		require.NoError(t, sendChunk(stream, chunk))
	}
}

// waitHandled waits until the handler made the row, then gives it a moment for the chunks in flight.
func waitHandled(t *testing.T, cfg *config.Config, id string) {
	t.Helper()
	require.Eventually(t, func() bool {
		_, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
		return err == nil
	}, 5*time.Second, 20*time.Millisecond, "the upload never made its row")
	time.Sleep(200 * time.Millisecond)
}

// waitStored waits until an upload stored size bytes of the recording.
func waitStored(t *testing.T, cfg *config.Config, id string, size int) *db.Recording {
	t.Helper()
	var rec *db.Recording
	require.Eventually(t, func() bool {
		var err error
		rec, err = cfg.Conn.Sys().GetRecording(t.Context(), id)
		return err == nil && rec.SizeBytes == int64(size)
	}, 10*time.Second, 20*time.Millisecond, "the upload was never stored")
	return rec
}

// startSecondCore runs another core on the shared config. stop is a deploy: the core shuts down and its streams end.
func startSecondCore(t *testing.T, cfg *config.Config) (client *http.Client, base string, stop func()) {
	t.Helper()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(free.Addr().String())
	require.NoError(t, err)
	require.NoError(t, free.Close())
	second := *cfg
	second.Port = port
	base = "http://127.0.0.1:" + port

	ctx, shutdown := context.WithCancel(context.WithoutCancel(t.Context()))
	stopped := make(chan error, 1)
	go func() { stopped <- api.New(&second).Start(ctx) }()
	require.Eventually(t, func() bool {
		resp, err := http.Get(base + "/healthz")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 20*time.Millisecond, "the second core never listened")

	stop = sync.OnceFunc(func() {
		shutdown()
		<-stopped
	})
	t.Cleanup(stop)
	// A client stream needs HTTP/2, which a proxy speaks to the core without TLS.
	var h2c http.Protocols
	h2c.SetUnencryptedHTTP2(true)
	return &http.Client{Transport: &http.Transport{Protocols: &h2c}}, base, stop
}

// openUploadAt is openUpload against any core.
func openUploadAt(
	ctx context.Context,
	t *testing.T,
	cfg *config.Config,
	client *http.Client,
	base string,
	key *ecdsa.PrivateKey,
	token, id string,
) uploadStream {
	t.Helper()
	ctx, call := connect.NewClientContext(ctx)
	call.RequestHeader().Set("Authorization", "DPoP "+token)
	call.RequestHeader().Set("DPoP",
		dpopProof(t, cfg, key, nokkuv1connect.DaemonControlServiceUploadRecordingProcedure, token))
	stream, err := nokkuv1connect.NewDaemonControlServiceClient(connect.NewClient(connecthttp.NewTransport(client, base))).
		UploadRecording(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&nokkuv1.UploadRecordingRequest{Msg: &nokkuv1.UploadRecordingRequest_Meta{
		Meta: &nokkuv1.RecordingMeta{RecordingId: &id, Username: new("root")},
	}}))
	return stream
}

// A deploy lands in the middle of a live upload. The old core stores what arrived and leaves the session open, the
// daemon's next try stores the whole recording, and a repeat of it is told the core holds it already.
func TestCoreRestartMidUploadEndsWithTheWholeRecordingOnce(t *testing.T) {
	selfHostedOnly(t, "it dials the real listener, which reads no workspace host")
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	token := enrolled.GetAccessToken()
	id := uuid.NewV7().String()
	whole := randomBytes(4 * pendingChunk)

	client, base, restart := startSecondCore(t, cfg)
	live := openUploadAt(t.Context(), t, cfg, client, base, key, token, id)
	sendLive(t, live, whole[:2*pendingChunk])
	waitHandled(t, cfg, id)
	start := time.Now()
	restart()
	assert.Less(t, time.Since(start), 4*time.Second, "the deploy waited out its grace on the upload")
	_, err := live.CloseAndReceive()
	assert.Equal(t, connect.CodeUnavailable, connect.CodeOf(err), "the daemon hears to try again, got %v", err)

	rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.NoError(t, err)
	assert.Nil(t, rec.EndedAt, "the session runs on through a deploy, it must stay listed as live")
	assert.False(t, rec.Complete)
	assert.EqualValues(t, 2*pendingChunk, rec.SizeBytes)
	assert.Equal(t, whole[:2*pendingChunk], storedCopy(t, cfg, id), "what arrived before the deploy is stored")
	part := objectOf(t, cfg, id)

	require.NoError(t, uploadFile(t, cfg, srv, key, token, id, whole, ""))
	rec, err = cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.NoError(t, err)
	assert.True(t, rec.Complete)
	assert.NotNil(t, rec.EndedAt, "the last message says the session ended")
	assert.EqualValues(t, len(whole), rec.SizeBytes)
	assert.Equal(t, whole, storedCopy(t, cfg, id), "the retry resumed the row and stored the file once")
	require.NoError(t, cfg.Record.DeleteQueued(t.Context()))
	assert.False(t, objectExists(workspaceID, part), "the part the whole file replaced stayed in storage")
	assert.True(t, objectExists(workspaceID, objectOf(t, cfg, id)), "the delete queue took the whole file")

	// The answer got lost on the way, so the daemon sends the file again.
	err = uploadFile(t, cfg, srv, key, token, id, whole, "")
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err), "got %v", err)
	again, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.NoError(t, err)
	assert.Equal(t, rec.EndedAt, again.EndedAt, "the refused repeat touched the row")
	assert.True(t, again.Complete)
	assert.Equal(t, whole, storedCopy(t, cfg, id))
}

// What a crashed daemon leaves is a flushed gzip stream without its footer. Sent with its cut reason it stays
// incomplete, and so does a file of which bytes went missing.
func TestCutOrShortRecordingIsNeverComplete(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	token := enrolled.GetAccessToken()
	var leftover bytes.Buffer
	zw := gzip.NewWriter(&leftover)
	const cast = `{"version":3,"term":{"cols":80,"rows":24}}` + "\n" + `[0.1,"o","typed before the crash"]` + "\n"
	_, err := zw.Write([]byte(cast))
	require.NoError(t, err)
	require.NoError(t, zw.Flush())

	cut := uuid.NewV7().String()
	const reason = "the daemon stopped before the recording was closed"
	require.NoError(t, uploadFile(t, cfg, srv, key, token, cut, leftover.Bytes(), reason))
	rec, err := cfg.Conn.Sys().GetRecording(t.Context(), cut)
	require.NoError(t, err)
	assert.False(t, rec.Complete, "a cut recording counts as whole")
	assert.Equal(t, leftover.Bytes(), storedCopy(t, cfg, cut), "what there is of it is kept")
	var events []*db.ListAuditLogsRow
	require.Eventually(t, func() bool {
		inWorkspace(t, cfg, workspaceID, func(q *db.Queries) (err error) {
			events, err = q.ListAuditLogs(t.Context(), &db.ListAuditLogsParams{
				Actions: []string{"UploadRecording"},
				Target:  &cut,
				Limit:   10,
			})
			return err
		})
		return len(events) == 1
	}, 5*time.Second, 20*time.Millisecond, "the upload left no audit event")
	assert.Contains(t, string(events[0].Details), reason, "the audit log does not say why the recording is cut")

	// The daemon's file is one chunk longer than what arrived.
	short := uuid.NewV7().String()
	stream := openUpload(t.Context(), t, cfg, srv, key, token, short)
	sendLive(t, stream, randomBytes(pendingChunk))
	require.NoError(t, stream.Send(finalOf(2*pendingChunk, "")))
	res, err := stream.CloseAndReceive()
	require.NoError(t, err)
	assert.EqualValues(t, pendingChunk, res.GetSizeBytes(), "the answer names what the core holds")
	rec, err = cfg.Conn.Sys().GetRecording(t.Context(), short)
	require.NoError(t, err)
	assert.False(t, rec.Complete, "a recording with bytes missing counts as whole")
}

// The larger copy wins, also over a shorter upload that calls itself whole.
func TestShorterWholeUploadKeepsTheLongerPart(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	token := enrolled.GetAccessToken()
	id := uuid.NewV7().String()
	part := randomBytes(3 * pendingChunk)

	ctx, die := context.WithCancel(t.Context())
	live := openUpload(ctx, t, cfg, srv, key, token, id)
	sendLive(t, live, part)
	waitHandled(t, cfg, id)
	die()
	waitStored(t, cfg, id, len(part))

	shorter := part[:pendingChunk]
	require.NoError(t, uploadFile(t, cfg, srv, key, token, id, shorter, ""))
	rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.NoError(t, err)
	assert.False(t, rec.Complete)
	assert.EqualValues(t, len(part), rec.SizeBytes)
	assert.Equal(t, part, storedCopy(t, cfg, id), "the shorter upload replaced what only the live stream had")
}

// A live stream the core has not seen end yet outlives the retry. When it ends, it sees the finished recording under
// the row lock and its object goes to the delete queue.
func TestStaleLiveStreamCannotReplaceTheFinishedRetry(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	token := enrolled.GetAccessToken()
	id := uuid.NewV7().String()
	whole := randomBytes(4 * pendingChunk)
	require.NoError(t, cfg.Record.DeleteQueued(t.Context()))
	before := storedObjects(t, workspaceID)

	live := openUpload(t.Context(), t, cfg, srv, key, token, id)
	sendLive(t, live, whole[:3*pendingChunk])
	waitHandled(t, cfg, id)

	require.NoError(t, uploadFile(t, cfg, srv, key, token, id, whole, ""))
	rec, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.NoError(t, err)
	require.True(t, rec.Complete)

	_, err = live.CloseAndReceive()
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err), "got %v", err)
	after, err := cfg.Conn.Sys().GetRecording(t.Context(), id)
	require.NoError(t, err)
	assert.True(t, after.Complete, "the stale stream turned a finished recording incomplete")
	assert.EqualValues(t, len(whole), after.SizeBytes)
	assert.Equal(t, rec.EndedAt, after.EndedAt)
	assert.Equal(t, whole, storedCopy(t, cfg, id), "the stale stream replaced the finished copy")
	require.NoError(t, cfg.Record.DeleteQueued(t.Context()))
	assert.ElementsMatch(t, append(before, objectOf(t, cfg, id)), storedObjects(t, workspaceID),
		"the stale stream left an object nothing tracks")
}

// Two first uploads of one recording race to make its row. The one that loses is told to try again. AlreadyExists
// would tell nokkud that the core holds the whole file, and it would delete its copy.
func TestRacingFirstUploadIsToldToRetry(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	id := uuid.NewV7().String()
	sealed, err := cfg.Keyset.Seal(recording.KeyAAD(workspaceID, id), recording.NewKey())
	require.NoError(t, err)

	// The other upload's row stays uncommitted until this upload's insert waits on it.
	made, commit := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(commit) })
	t.Cleanup(release)
	other := make(chan error, 1)
	go func() {
		other <- cfg.Conn.TenantTx(wsCtx(t, cfg), func(q *db.Queries) error {
			_, err := q.CreateRecording(t.Context(), &db.CreateRecordingParams{
				ID:       id,
				DaemonID: enrolled.GetId(),
				Username: "root",
				Key:      sealed,
			})
			close(made)
			if err != nil {
				return err
			}
			<-commit
			return nil
		})
	}()
	<-made

	stream := openUpload(t.Context(), t, cfg, srv, key, enrolled.GetAccessToken(), id)
	require.Eventually(t, func() bool {
		var waiting bool
		err := cfg.Conn.Pool.QueryRow(wsCtx(t, cfg), `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
			WHERE wait_event_type = 'Lock' AND query LIKE '%name: CreateRecording%')`).Scan(&waiting)
		return err == nil && waiting
	}, 5*time.Second, 20*time.Millisecond, "the upload never waited on the other row")
	release()
	require.NoError(t, <-other)

	_, err = stream.CloseAndReceive()
	assert.Equal(t, connect.CodeAborted, connect.CodeOf(err), "got %v", err)
}
