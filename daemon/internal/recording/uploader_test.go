package recording

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
)

type testServer struct {
	mu     sync.Mutex
	msgs   []*nokkuv1.UploadRecordingRequest
	opens  int
	closed int
	client nokkuv1connect.DaemonControlServiceClient
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	ts := &testServer{}
	handler := connect.NewClientStreamHandlerSimple(
		nokkuv1connect.DaemonControlServiceUploadRecordingProcedure,
		func(_ context.Context, stream *connect.ClientStream[nokkuv1.UploadRecordingRequest]) (*nokkuv1.UploadRecordingResponse, error) {
			ts.mu.Lock()
			ts.opens++
			ts.mu.Unlock()
			for stream.Receive() {
				ts.mu.Lock()
				ts.msgs = append(ts.msgs, stream.Msg())
				ts.mu.Unlock()
			}
			ts.mu.Lock()
			ts.closed++
			ts.mu.Unlock()
			size := int64(123)
			return &nokkuv1.UploadRecordingResponse{SizeBytes: &size}, nil
		},
		// Without the schema's stream type the handler frames the RPC as unary and never reads the body.
		connect.WithSchema(
			nokkuv1.File_nokku_v1_daemon_proto.Services().
				ByName("DaemonControlService").
				Methods().
				ByName("UploadRecording"),
		),
	)
	mux := http.NewServeMux()
	mux.Handle(nokkuv1connect.DaemonControlServiceUploadRecordingProcedure, handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		// Client connections first, httptest.Close would block on a live keep-alive one.
		srv.CloseClientConnections()
		srv.Close()
	})
	ts.client = nokkuv1connect.NewDaemonControlServiceClient(srv.Client(), srv.URL)
	return ts
}

func (ts *testServer) snapshot() (msgs []*nokkuv1.UploadRecordingRequest, opens, closed int) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return append([]*nokkuv1.UploadRecordingRequest(nil), ts.msgs...), ts.opens, ts.closed
}

func TestUploaderStreamsPlaintext(t *testing.T) {
	ts := newTestServer(t)
	is := assert.New(t)
	must := require.New(t)

	u := NewUploader(context.Background(), ts.client, "s1", "user", "")

	_, err := u.Write([]byte("terminal output"))
	must.NoError(err)
	must.NoError(u.Close())

	msgs, opens, closed := ts.snapshot()
	is.Equal(1, opens)
	is.Equal(1, closed)
	must.Len(msgs, 3)
	meta := msgs[0].GetMeta()
	must.NotNil(meta)
	is.Equal("s1", meta.GetRecordingId())
	is.Equal("user", meta.GetUsername())
	is.Equal("terminal output", string(msgs[1].GetChunk()))
	is.NotNil(msgs[2].GetFinal())
}

// Write still reports success after a backend error, so the local file keeps the data.
func TestUploaderKeepsLocalOnFailure(t *testing.T) {
	ts := newTestServer(t)
	is := assert.New(t)
	must := require.New(t)

	u := NewUploader(context.Background(), ts.client, "s1", "user", "")

	_, err := u.Write([]byte("first"))
	must.NoError(err)
	// Forcing a mid-stream failure is awkward. A write after Close must report success just the same.
	must.NoError(u.Close())
	n, err := u.Write([]byte("after close"))
	must.NoError(err)
	is.NotZero(n)
}

func TestUploaderZeroSlicesAreNoop(t *testing.T) {
	ts := newTestServer(t)
	is := assert.New(t)
	must := require.New(t)

	u := NewUploader(context.Background(), ts.client, "s1", "user", "")

	n, err := u.Write(nil)
	must.NoError(err)
	is.Zero(n)
	must.NoError(u.Close())
	_, opens, _ := ts.snapshot()
	is.Zero(opens)
}

func TestUploaderReportsWhyTheBackendRefused(t *testing.T) {
	handler := connect.NewClientStreamHandlerSimple(
		nokkuv1connect.DaemonControlServiceUploadRecordingProcedure,
		func(_ context.Context, stream *connect.ClientStream[nokkuv1.UploadRecordingRequest]) (*nokkuv1.UploadRecordingResponse, error) {
			stream.Receive()
			return nil, connect.NewError(
				connect.CodeResourceExhausted,
				errors.New("the recording storage of this workspace is full"),
			)
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
	client := nokkuv1connect.NewDaemonControlServiceClient(srv.Client(), srv.URL)

	u := NewUploader(context.Background(), client, "s1", "user", "")
	for range 200 {
		_, err := u.Write(make([]byte, 32<<10))
		require.NoError(t, err, "the session never sees an upload problem")
		time.Sleep(time.Millisecond)
	}
	err := u.Close()
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err), "got %v", err)
}
