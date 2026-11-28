package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
)

type relayOnly struct {
	nokkuv1connect.UnimplementedDaemonServiceHandler

	relay *Relay
}

func (h relayOnly) Relay(ctx context.Context, stream nokkuv1connect.DaemonServiceRelayServerStream) error {
	ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	return BridgeRelay(ctx, stream, h.relay)
}

// An idle relay ends with its ctx, so MaxRelayTime holds on the core too.
func TestBridgeRelayEndsWithItsContext(t *testing.T) {
	relay := &Relay{toDaemon: make(chan []byte, 1), toUser: make(chan []byte, 1), closed: make(chan struct{})}
	server := connect.NewServer()
	nokkuv1connect.RegisterDaemonServiceHandler(server, relayOnly{relay: relay})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client := nokkuv1connect.NewDaemonServiceClient(connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL)))
	stream, err := client.Relay(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&nokkuv1.RelayRequest{}))
	res, err := stream.Receive()
	require.NoError(t, err, "the relay outlived its ctx")
	assert.NotNil(t, res.GetClosed(), "the relay ended without saying so")
}
