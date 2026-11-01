package recording

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

// coreUpload is one upload stream the way the core saw it.
type coreUpload struct {
	meta  *nokkuv1.RecordingMeta
	data  []byte
	final *nokkuv1.RecordingFinal
	// Why the stream ended, nil for a clean end.
	err error
}

// fakeCore speaks HTTP/2 without TLS, like the core behind its proxy, so a
// child process reaches it too. answer runs after the meta, an error ends it.
type fakeCore struct {
	url    string
	client nokkuv1connect.DaemonControlServiceClient
	answer func(context.Context, *nokkuv1.RecordingMeta) error

	srv *http.Server
	mu  sync.Mutex
	// uploads has every stream, in the order they opened.
	uploads []*coreUpload
}

type uploadHandler struct {
	nokkuv1connect.UnimplementedDaemonControlServiceHandler

	core *fakeCore
}

// complete is what the real core decides: no cut and every byte arrived.
func (up coreUpload) complete() bool {
	return up.final != nil && up.final.GetCutReason() == "" && up.final.GetSizeBytes() == int64(len(up.data))
}

func newFakeCore(t *testing.T, answer func(context.Context, *nokkuv1.RecordingMeta) error) *fakeCore {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	c := &fakeCore{url: "http://" + l.Addr().String(), answer: answer}
	c.serve(l)
	t.Cleanup(c.stop)
	c.client = coreClient(c.url)
	return c
}

func coreClient(url string) nokkuv1connect.DaemonControlServiceClient {
	var h2c http.Protocols
	h2c.SetUnencryptedHTTP2(true)
	httpc := &http.Client{Transport: &http.Transport{Protocols: &h2c}}
	return nokkuv1connect.NewDaemonControlServiceClient(connect.NewClient(connecthttp.NewTransport(httpc, url)))
}

func (c *fakeCore) serve(l net.Listener) {
	server := connect.NewServer()
	nokkuv1connect.RegisterDaemonControlServiceHandler(server, uploadHandler{core: c})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	var h2c http.Protocols
	h2c.SetUnencryptedHTTP2(true)
	c.srv = &http.Server{Handler: mux, Protocols: &h2c, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = c.srv.Serve(l) }()
}

func (c *fakeCore) stop() { _ = c.srv.Close() }

// restart is a deploy: streams break, a new core takes the same address.
func (c *fakeCore) restart(t *testing.T) {
	t.Helper()
	c.stop()
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", strings.TrimPrefix(c.url, "http://"))
	require.NoError(t, err)
	c.serve(l)
}

func (h uploadHandler) UploadRecording(
	ctx context.Context,
	stream nokkuv1connect.DaemonControlServiceUploadRecordingServerStream,
) (*nokkuv1.UploadRecordingResponse, error) {
	c := h.core
	first, err := stream.Receive()
	if err != nil {
		return nil, err
	}
	up := &coreUpload{meta: first.GetMeta()}
	c.mu.Lock()
	c.uploads = append(c.uploads, up)
	c.mu.Unlock()
	if c.answer != nil {
		if err = c.answer(ctx, up.meta); err != nil {
			c.end(up, err)
			return nil, err
		}
	}
	for {
		msg, recvErr := stream.Receive()
		if errors.Is(recvErr, io.EOF) {
			c.mu.Lock()
			defer c.mu.Unlock()
			return &nokkuv1.UploadRecordingResponse{SizeBytes: new(int64(len(up.data)))}, nil
		}
		if recvErr != nil {
			c.end(up, recvErr)
			return nil, recvErr
		}
		c.mu.Lock()
		up.data = append(up.data, msg.GetChunk()...)
		if f := msg.GetFinal(); f != nil {
			up.final = f
		}
		c.mu.Unlock()
	}
}

func (c *fakeCore) end(up *coreUpload, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	up.err = err
}

func (c *fakeCore) snapshot() []coreUpload {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]coreUpload, 0, len(c.uploads))
	for _, up := range c.uploads {
		cp := *up
		cp.data = bytes.Clone(up.data)
		out = append(out, cp)
	}
	return out
}

// waitFinal waits for n streams, the last one ended with its final message.
func (c *fakeCore) waitFinal(t *testing.T, n int) []coreUpload {
	t.Helper()
	var uploads []coreUpload
	require.Eventually(t, func() bool {
		uploads = c.snapshot()
		return len(uploads) == n && uploads[n-1].final != nil
	}, 10*time.Second, 10*time.Millisecond, "the core never got %d uploads, the last one finished", n)
	return uploads
}

func newRecordsDir(t *testing.T) string {
	t.Helper()
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	dir := paths.RecordsDir()
	require.NoError(t, os.MkdirAll(dir, 0o700))
	return dir
}

// fastRetries makes failed uploads and full workspaces retry almost at once.
func fastRetries(t *testing.T) {
	t.Helper()
	first, last, full := firstRetry, lastRetry, retryWhenFull
	firstRetry, lastRetry, retryWhenFull = 10*time.Millisecond, 50*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { firstRetry, lastRetry, retryWhenFull = first, last, full })
}

// startUploads runs uploads for one test, whose end stops and awaits them.
func startUploads(t *testing.T, core *fakeCore) *Uploads {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	u := NewUploads(ctx, core.client)
	t.Cleanup(func() {
		cancel()
		u.Wait(5 * time.Second)
	})
	return u
}

func newRecorder(t *testing.T, opts Options) *Recorder {
	t.Helper()
	opts.Width, opts.Height = 80, 24
	if opts.SessionID == "" {
		opts.SessionID = uuid.NewV7().String()
	}
	opts.User = "alice"
	rec, err := New(opts)
	require.NoError(t, err)
	return rec
}

// unzipCast returns the text and read error, ErrUnexpectedEOF for a cut cast.
func unzipCast(data []byte) (string, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	text, err := io.ReadAll(zr)
	return string(text), err
}

func gzipText(t *testing.T, text string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write([]byte(text))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// waitOnDisk waits for the flush loop to get text into the file.
func waitOnDisk(t *testing.T, path, text string) {
	t.Helper()
	require.Eventually(t, func() bool {
		data, _ := os.ReadFile(path)
		got, _ := unzipCast(data)
		return strings.Contains(got, text)
	}, 5*time.Second, 10*time.Millisecond, "%q never reached the file", text)
}

// waitReceived waits until the core's latest stream carried text.
func (c *fakeCore) waitReceived(t *testing.T, text string) {
	t.Helper()
	require.Eventually(t, func() bool {
		uploads := c.snapshot()
		if len(uploads) == 0 {
			return false
		}
		got, _ := unzipCast(uploads[len(uploads)-1].data)
		return strings.Contains(got, text)
	}, 10*time.Second, 10*time.Millisecond, "%q never reached the core", text)
}

func noiseLine(size int) []byte {
	raw := make([]byte, size)
	_, _ = rand.Read(raw)
	return []byte(base64.StdEncoding.EncodeToString(raw))
}
