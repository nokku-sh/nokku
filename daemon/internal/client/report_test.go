package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/daemon/internal/report"
	"github.com/nokku-sh/nokku/daemon/internal/state"
)

// reportCore takes connection reports like the real core. While deaf it takes them and never acks, like a core
// that died between the two.
type reportCore struct {
	nokkuv1connect.UnimplementedDaemonControlServiceHandler

	reports chan *nokkuv1.ConnectionReport
	deaf    atomic.Bool
}

func (c *reportCore) Connect(
	_ context.Context,
	stream nokkuv1connect.DaemonControlServiceConnectServerStream,
) error {
	for {
		req, err := stream.Receive()
		if err != nil {
			return err
		}
		r := req.GetConnectionReport()
		if r == nil {
			continue
		}
		c.reports <- r
		if c.deaf.Load() {
			continue
		}
		if err = stream.Send(&nokkuv1.ConnectResponse{Msg: &nokkuv1.ConnectResponse_ConnectionReportAck{
			ConnectionReportAck: &nokkuv1.ConnectionReportAck{},
		}}); err != nil {
			return err
		}
	}
}

// A login while the core is away is reported once it is back. Nothing leaves the spool before the core acked it,
// so a report whose ack got lost goes out again on the next stream.
func TestConnectionReportsWaitForTheAck(t *testing.T) {
	core := &reportCore{reports: make(chan *nokkuv1.ConnectionReport, 4)}
	server := connect.NewServer()
	nokkuv1connect.RegisterDaemonControlServiceHandler(server, core)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
	})
	c := &Client{
		state:   state.New(state.Config{}),
		reports: report.Open(filepath.Join(t.TempDir(), "connections.jsonl")),
		ctl: nokkuv1connect.NewDaemonControlServiceClient(
			connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL)),
		),
	}
	stream := func() (stop func()) {
		ctx, cancel := context.WithCancel(t.Context())
		ended := make(chan struct{})
		go func() {
			defer close(ended)
			_ = c.runControlStream(ctx)
		}()
		return func() {
			cancel()
			<-ended
		}
	}
	next := func() *nokkuv1.ConnectionReport {
		t.Helper()
		select {
		case r := <-core.reports:
			return r
		case <-time.After(5 * time.Second):
			t.Fatal("no connection report reached the core")
			return nil
		}
	}
	spooled := func() int {
		events, _ := c.reports.Next()
		return len(events)
	}

	// The SSH server spools a login and its end with no stream up.
	at := time.Now().Truncate(time.Second)
	c.reports.Add(report.Event{ConnectionID: "c1", Time: at, Principal: principal("deploy"), KeyID: "key", Remote: "r"})
	c.reports.Add(report.Event{ConnectionID: "c1", Closed: true, Time: at, Principal: principal("deploy")})

	core.deaf.Store(true)
	stop := stream()
	first := next()
	require.Len(t, first.GetEvents(), 2)
	opened, closed := first.GetEvents()[0], first.GetEvents()[1]
	assert.Equal(t, "c1", opened.GetConnectionId())
	assert.False(t, opened.GetClosed())
	assert.True(t, closed.GetClosed())
	assert.Equal(t, principal("deploy"), opened.GetPrincipal())
	assert.Equal(t, "key", opened.GetKeyId())
	assert.True(t, at.Equal(opened.GetTime().AsTime()))
	stop()
	require.Equal(t, 2, spooled(), "a report left the spool without an ack")

	core.deaf.Store(false)
	stop = stream()
	defer stop()
	again := next()
	require.Len(t, again.GetEvents(), 2, "the next stream did not send the report again")
	require.Eventually(t, func() bool { return spooled() == 0 }, 5*time.Second, 10*time.Millisecond,
		"an acked report stayed in the spool")

	// With the stream up a login goes out at once.
	c.reports.Add(report.Event{ConnectionID: "c2", Time: at, Principal: principal("deploy")})
	live := next()
	require.Len(t, live.GetEvents(), 1)
	assert.Equal(t, "c2", live.GetEvents()[0].GetConnectionId())
}

// One event with a byte the wire refuses must not hold back every report after it.
func TestAReportWithABadByteStillGoesOut(t *testing.T) {
	msg := connectionReport([]report.Event{{ConnectionID: "c1", Client: "SSH-2.0-\xffbad", Remote: "r\xfe"}}, 0)
	_, err := proto.Marshal(msg)
	require.NoError(t, err)
	assert.Equal(t, "SSH-2.0-bad", msg.GetConnectionReport().GetEvents()[0].GetClientVersion())
}
