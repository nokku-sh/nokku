package recording

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
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

// uploadCore is a core that only takes uploads.
type uploadCore struct {
	nokkuv1connect.UnimplementedDaemonControlServiceHandler

	handle func(context.Context, nokkuv1connect.DaemonControlServiceUploadRecordingServerStream) (*nokkuv1.UploadRecordingResponse, error)
}

func (c uploadCore) UploadRecording(
	ctx context.Context,
	stream nokkuv1connect.DaemonControlServiceUploadRecordingServerStream,
) (*nokkuv1.UploadRecordingResponse, error) {
	return c.handle(ctx, stream)
}

func uploadMux(
	handle func(context.Context, nokkuv1connect.DaemonControlServiceUploadRecordingServerStream) (*nokkuv1.UploadRecordingResponse, error),
) *http.ServeMux {
	server := connect.NewServer()
	nokkuv1connect.RegisterDaemonControlServiceHandler(server, uploadCore{handle: handle})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	return mux
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	ts := &testServer{}
	mux := uploadMux(
		func(_ context.Context, stream nokkuv1connect.DaemonControlServiceUploadRecordingServerStream) (*nokkuv1.UploadRecordingResponse, error) {
			ts.mu.Lock()
			ts.opens++
			ts.mu.Unlock()
			for {
				msg, err := stream.Receive()
				if err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					return nil, err
				}
				ts.mu.Lock()
				ts.msgs = append(ts.msgs, msg)
				ts.mu.Unlock()
			}
			ts.mu.Lock()
			ts.closed++
			ts.mu.Unlock()
			size := int64(123)
			return &nokkuv1.UploadRecordingResponse{SizeBytes: &size}, nil
		},
	)
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		// Client connections first, httptest.Close would block on a live keep-alive one.
		srv.CloseClientConnections()
		srv.Close()
	})
	ts.client = nokkuv1connect.NewDaemonControlServiceClient(
		connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL)),
	)
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

// Write still reports success after a core error, so the local file keeps the data.
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
	mux := uploadMux(
		func(_ context.Context, stream nokkuv1connect.DaemonControlServiceUploadRecordingServerStream) (*nokkuv1.UploadRecordingResponse, error) {
			_, _ = stream.Receive()
			return nil, connect.NewError(
				connect.CodeResourceExhausted,
				"the recording storage of this workspace is full",
			)
		},
	)
	// HTTP/2 like the daemon, HTTP/1.1 does not end a request body early.
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
	})
	client := nokkuv1connect.NewDaemonControlServiceClient(
		connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL)),
	)

	u := NewUploader(context.Background(), client, "s1", "user", "")
	for range 200 {
		_, err := u.Write(make([]byte, 32<<10))
		require.NoError(t, err, "the session never sees an upload problem")
		time.Sleep(time.Millisecond)
	}
	err := u.Close()
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err), "got %v", err)
}
