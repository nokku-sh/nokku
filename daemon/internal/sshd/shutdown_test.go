package sshd

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
	"github.com/nokku-sh/nokku/daemon/internal/recording"
)

// recordingsCore keeps what each upload stream carried.
type recordingsCore struct {
	nokkuv1connect.UnimplementedDaemonControlServiceHandler

	mu     sync.Mutex
	data   []byte
	final  *nokkuv1.RecordingFinal
	client nokkuv1connect.DaemonControlServiceClient
}

func newRecordingsCore(t *testing.T) *recordingsCore {
	t.Helper()
	c := &recordingsCore{}
	server := connect.NewServer()
	nokkuv1connect.RegisterDaemonControlServiceHandler(server, c)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	// HTTP/2 like the daemon, HTTP/1.1 does not end a request body early.
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
	})
	c.client = nokkuv1connect.NewDaemonControlServiceClient(
		connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL)),
	)
	return c
}

func (c *recordingsCore) UploadRecording(
	_ context.Context,
	stream nokkuv1connect.DaemonControlServiceUploadRecordingServerStream,
) (*nokkuv1.UploadRecordingResponse, error) {
	c.mu.Lock()
	c.data, c.final = nil, nil
	c.mu.Unlock()
	for {
		msg, err := stream.Receive()
		if errors.Is(err, io.EOF) {
			c.mu.Lock()
			defer c.mu.Unlock()
			return &nokkuv1.UploadRecordingResponse{SizeBytes: new(int64(len(c.data)))}, nil
		}
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.data = append(c.data, msg.GetChunk()...)
		if f := msg.GetFinal(); f != nil {
			c.final = f
		}
		c.mu.Unlock()
	}
}

// A stop hangs up a live session, its recording still reaches the core whole.
func TestShutdownWithALiveSessionUploadsTheRecording(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	must.NoError(paths.Verify())
	core := newRecordingsCore(t)

	ctx, stop := context.WithCancel(t.Context())
	uploads := recording.NewUploads(ctx, core.client)
	srv, err := New(uploads, nil)
	must.NoError(err)
	srv.SetAccess(testAccess(t, ca))
	withPolicy(policy{Record: true})(srv)
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	must.NoError(err)
	served := make(chan struct{})
	go func() {
		defer close(served)
		srv.Serve(ctx, l)
	}()

	client, err := dial(t, l.Addr().String(), currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err)
	defer client.Close()
	sess, err := client.NewSession()
	must.NoError(err)
	defer sess.Close()
	must.NoError(sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{}))
	stdout, err := sess.StdoutPipe()
	must.NoError(err)
	must.NoError(sess.Start("echo still-running; exec sleep 60"))
	out := bufio.NewReader(stdout)
	notice, err := out.ReadString('\n')
	must.NoError(err)
	must.Equal(recordedNotice, notice)
	line, err := out.ReadString('\n')
	must.NoError(err)
	must.Contains(line, "still-running")

	stop()
	select {
	case <-served:
	case <-time.After(hangupGrace + 5*time.Second):
		t.Fatal("Serve did not wait for the session and return")
	}
	must.Error(sess.Wait(), "the session outlived the daemon")
	must.True(uploads.Wait(5*time.Second), "the recording was still uploading")

	core.mu.Lock()
	defer core.mu.Unlock()
	must.NotNil(core.final, "the recording never finished its upload")
	is.Empty(core.final.GetCutReason())
	is.EqualValues(len(core.data), core.final.GetSizeBytes(), "the core is missing part of the recording")
	zr, err := gzip.NewReader(bytes.NewReader(core.data))
	must.NoError(err)
	cast, err := io.ReadAll(zr)
	must.NoError(err, "the recording is no whole gzip stream")
	is.Contains(string(cast), "still-running")
	is.Contains(string(cast), `"x"`, "the hung up session has no exit event")
}
