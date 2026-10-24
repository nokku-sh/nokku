package recording

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
)

type resultSink struct {
	err  error
	done chan struct{}
}

func (s *resultSink) Write(p []byte) (int, error) { return len(p), nil }

func (s *resultSink) Close() error {
	defer close(s.done)
	return s.err
}

func recordOnce(t *testing.T, sink *resultSink) {
	t.Helper()
	rec, err := New(Options{
		Width: 80, Height: 24, Title: "t", User: "alice",
		SessionID: "0199aaaa-0000-7000-8000-000000000001", Sink: sink,
	})
	require.NoError(t, err)
	rec.RecordOutput([]byte("hello"))
	rec.Close()
	<-sink.done
}

func TestRecorderRemovesConfirmedUpload(t *testing.T) {
	dir := newRecordsDir(t)
	recordOnce(t, &resultSink{done: make(chan struct{})})

	require.Eventually(t, func() bool {
		entries, err := os.ReadDir(dir)
		return err == nil && len(entries) == 0
	}, time.Second, 10*time.Millisecond, "confirmed upload was not removed")
}

func TestRecorderKeepsFailedUploadPending(t *testing.T) {
	dir := newRecordsDir(t)
	recordOnce(t, &resultSink{err: errors.New("core down"), done: make(chan struct{})})

	// Wait until the recorder let go of the file, then it must be pending.
	require.Eventually(t, func() bool {
		m, _ := filepath.Glob(filepath.Join(dir, "*"+castSuffix))
		if len(m) != 1 {
			return false
		}
		_, busy := active.Load(m[0])
		return !busy
	}, time.Second, 10*time.Millisecond, "a failed upload must stay pending")
}

func TestUploadPending(t *testing.T) {
	dir := newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)
	ts := newTestServer(t)

	recordOnce(t, &resultSink{err: errors.New("core down"), done: make(chan struct{})})
	require.Eventually(t, func() bool {
		m, _ := filepath.Glob(filepath.Join(dir, "*"+castSuffix))
		if len(m) != 1 {
			return false
		}
		_, busy := active.Load(m[0])
		return !busy
	}, time.Second, 10*time.Millisecond)
	pending, _ := filepath.Glob(filepath.Join(dir, "*"+castSuffix))
	must.Len(pending, 1)
	data, err := os.ReadFile(pending[0])
	must.NoError(err)

	must.NoError(UploadPending(t.Context(), ts.client))

	msgs, opens, _ := ts.snapshot()
	is.Equal(1, opens)
	must.NotEmpty(msgs)
	is.Equal("0199aaaa-0000-7000-8000-000000000001", msgs[0].GetMeta().GetRecordingId())
	is.Equal("alice", msgs[0].GetMeta().GetUsername())
	is.WithinDuration(time.Now(), msgs[0].GetMeta().GetStartedAt().AsTime(), time.Minute,
		"a late upload says when the session began")
	var sent []byte
	for _, m := range msgs[1 : len(msgs)-1] {
		sent = append(sent, m.GetChunk()...)
	}
	is.Equal(data, sent, "the file must be uploaded byte for byte")
	is.NotNil(msgs[len(msgs)-1].GetFinal())

	left, err := os.ReadDir(dir)
	must.NoError(err)
	is.Empty(left, "an uploaded recording must not stay on disk")

	// Nothing is left to upload.
	must.NoError(UploadPending(t.Context(), ts.client))
	_, opens, _ = ts.snapshot()
	is.Equal(1, opens)
}

// answeringCore is a core whose upload handler answers the nth call with what answer returns.
func answeringCore(t *testing.T, answer func(call int) error) nokkuv1connect.DaemonControlServiceClient {
	t.Helper()
	var calls atomic.Int32
	handler := connect.NewClientStreamHandlerSimple(
		nokkuv1connect.DaemonControlServiceUploadRecordingProcedure,
		func(_ context.Context, stream *connect.ClientStream[nokkuv1.UploadRecordingRequest]) (*nokkuv1.UploadRecordingResponse, error) {
			stream.Receive()
			if err := answer(int(calls.Add(1))); err != nil {
				return nil, err
			}
			for stream.Receive() {
			}
			return &nokkuv1.UploadRecordingResponse{}, nil
		},
		connect.WithSchema(
			nokkuv1.File_nokku_v1_daemon_proto.Services().
				ByName("DaemonControlService").
				Methods().
				ByName("UploadRecording"),
		),
	)
	mux := http.NewServeMux()
	mux.Handle(nokkuv1connect.DaemonControlServiceUploadRecordingProcedure, handler)
	// HTTP/2 like the daemon, HTTP/1.1 does not end a request body early.
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
	})
	return nokkuv1connect.NewDaemonControlServiceClient(srv.Client(), srv.URL)
}

// pendingRecording leaves one recording on disk whose live upload failed.
func pendingRecording(t *testing.T, dir string) string {
	t.Helper()
	recordOnce(t, &resultSink{err: errors.New("core down"), done: make(chan struct{})})
	var path string
	require.Eventually(t, func() bool {
		m, _ := filepath.Glob(filepath.Join(dir, "*"+castSuffix))
		if len(m) != 1 {
			return false
		}
		path = m[0]
		_, busy := active.Load(path)
		return !busy
	}, time.Second, 10*time.Millisecond)
	return path
}

// The answer keeps its code on the way out, the retry loop reads it to wait longer.
func TestUploadPendingReportsAFullWorkspace(t *testing.T) {
	dir := newRecordsDir(t)
	client := answeringCore(t, func(int) error {
		return connect.NewError(
			connect.CodeResourceExhausted,
			errors.New("the recording storage of this workspace is full"),
		)
	})
	pendingRecording(t, dir)

	err := UploadPending(t.Context(), client)
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err), "got %v", err)
	left, _ := filepath.Glob(filepath.Join(dir, "*"+castSuffix))
	assert.Len(t, left, 1, "a refused recording must stay on disk")
}

// A file the core keeps failing on stays for the next round and does not hold up the one behind it.
func TestUploadPendingGoesOnAfterAFailedFile(t *testing.T) {
	dir := newRecordsDir(t)
	client := answeringCore(t, func(call int) error {
		if call == 1 {
			return connect.NewError(connect.CodeInternal, errors.New("something went wrong"))
		}
		return nil
	})
	first := pendingRecording(t, dir)
	data, err := os.ReadFile(first)
	require.NoError(t, err)
	// Sorts behind the timestamp names, so it is the second upload.
	second := filepath.Join(dir, "zz"+castSuffix)
	require.NoError(t, os.WriteFile(second, data, 0o600))

	err = UploadPending(t.Context(), client)
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err), "the failed file is reported, got %v", err)
	left, _ := filepath.Glob(filepath.Join(dir, "*"+castSuffix))
	assert.Equal(t, []string{first}, left, "the failed file stays, the one behind it is uploaded")
}
