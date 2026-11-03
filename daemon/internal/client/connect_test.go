package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/daemon/internal/state"
)

// silentCore holds the control stream open and says nothing, like a healthy core.
type silentCore struct {
	nokkuv1connect.UnimplementedDaemonControlServiceHandler

	connected chan struct{}
	release   chan struct{}
}

func (c *silentCore) Connect(
	ctx context.Context,
	stream nokkuv1connect.DaemonControlServiceConnectServerStream,
) error {
	// The first message carries the response headers, as with the real core.
	if err := stream.Send(&nokkuv1.ConnectResponse{}); err != nil {
		return err
	}
	close(c.connected)
	select {
	case <-c.release:
	case <-ctx.Done():
	}
	return nil
}

func (c *silentCore) DaemonRelay(
	ctx context.Context,
	stream nokkuv1connect.DaemonControlServiceDaemonRelayServerStream,
) error {
	if err := stream.Send(&nokkuv1.DaemonRelayResponse{}); err != nil {
		return err
	}
	close(c.connected)
	select {
	case <-c.release:
	case <-ctx.Done():
	}
	return nil
}

// silentClient is a Client of a core that never answers, over real HTTP/2.
func silentClient(t *testing.T) (*Client, *silentCore) {
	t.Helper()
	core := &silentCore{connected: make(chan struct{}), release: make(chan struct{})}
	server := connect.NewServer()
	nokkuv1connect.RegisterDaemonControlServiceHandler(server, core)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	// Only on HTTP/2 does a read wait on the request's body.
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(func() {
		close(core.release)
		srv.CloseClientConnections()
		srv.Close()
	})
	return &Client{
		state: state.New(state.Config{}),
		ctl: nokkuv1connect.NewDaemonControlServiceClient(
			connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL)),
		),
	}, core
}

// idleRelay opens a relay to a silent core and parks a read on it.
func idleRelay(t *testing.T) (*relayConn, context.CancelFunc, <-chan error) {
	t.Helper()
	c, core := silentClient(t)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	stream, err := c.ctl.DaemonRelay(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&nokkuv1.DaemonRelayRequest{}))
	<-core.connected
	conn := &relayConn{stream: stream, cancel: cancel}
	read := make(chan error, 1)
	go func() {
		_, readErr := conn.Read(make([]byte, 16))
		if readErr == nil {
			_, readErr = conn.Read(make([]byte, 16))
		}
		read <- readErr
	}()
	time.Sleep(100 * time.Millisecond)
	return conn, cancel, read
}

// A relay left open would hold up a stop just the same, in Run's join.
func TestRelayEndsWithItsContext(t *testing.T) {
	conn, _, read := idleRelay(t)

	require.NoError(t, conn.Close())
	select {
	case readErr := <-read:
		require.Error(t, readErr)
	case <-time.After(3 * time.Second):
		t.Fatal("the relay outlived its Close")
	}
}

// On a stop the sshd closes the relay after its context ends, so no Closed frame goes out.
func TestRelayEndsOnStop(t *testing.T) {
	conn, cancel, read := idleRelay(t)

	cancel()
	require.NoError(t, conn.Close())
	select {
	case readErr := <-read:
		require.Error(t, readErr)
	case <-time.After(3 * time.Second):
		t.Fatal("the relay outlived the stop")
	}
}

// A stop can't wait for the core to notice the silence, that takes two minutes.
func TestControlStreamEndsWithItsContext(t *testing.T) {
	c, core := silentClient(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ended := make(chan error, 1)
	go func() { ended <- c.runControlStream(ctx) }()
	<-core.connected
	// Past the first heartbeat, so the sender is parked on its ticker.
	time.Sleep(100 * time.Millisecond)

	cancel()
	select {
	case err := <-ended:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("the control stream outlived its context")
	}
}
