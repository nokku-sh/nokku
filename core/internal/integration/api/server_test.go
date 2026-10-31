//go:build integration

package api_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/api"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// A public RPC must not buffer a body of any size before it is even validated.
func TestRequestSizeLimit(t *testing.T) {
	_, srv := newTestAPI(t)
	_, err := nokkuv1connect.NewAuthServiceClient(connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL))).
		ConsumeMagicLink(t.Context(), &nokkuv1.ConsumeMagicLinkRequest{
			Token: new(strings.Repeat("x", maxMessageBytes+1)),
		})
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err), "got %v", err)
}

// Settings that name no daemon defaults read as the built-in ones.
func TestWorkspaceReadsBuiltInDaemonDefaults(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	inWorkspace(t, cfg, workspaceID, func(q *db.Queries) error {
		_, err := q.UpdateWorkspace(t.Context(), &db.UpdateWorkspaceParams{Settings: &nokkuv1.WorkspaceSettings{}})
		return err
	})

	member := seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	got, err := nokkuv1connect.NewWorkspaceServiceClient(connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), header("Authorization", "Bearer "+member))).
		GetWorkspace(t.Context(), &nokkuv1.GetWorkspaceRequest{})
	require.NoError(t, err)
	assert.True(t,
		proto.Equal(db.DefaultDaemonConfig(), got.GetWorkspace().GetSettings().GetDefaultDaemonConfig()),
		"daemon defaults nobody set read as the built-in ones")
}

// The API needs no client library: a procedure is a JSON POST to its path.
func TestPlainJSONCall(t *testing.T) {
	_, srv := newTestAPI(t)
	resp, err := srv.Client().Post(
		srv.URL+nokkuv1connect.AuthServiceConsumeMagicLinkProcedure,
		"application/json",
		strings.NewReader(`{"token":"not-a-link"}`),
	)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, string(body), `"code":"unauthenticated"`)
}

// A newer client may call a service this build does not have. It must get a 404, not the SPA's index page.
func TestUnknownServiceIsNotFound(t *testing.T) {
	_, srv := newTestAPI(t)
	resp, err := srv.Client().Post(srv.URL+"/nokku.v1.FutureService/Do", "application/json", strings.NewReader(`{}`))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// A deploy lets a request that is under way finish, and ends the streams at once.
func TestShutdownLetsARequestFinish(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	member := seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)

	free, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(free.Addr().String())
	require.NoError(t, err)
	require.NoError(t, free.Close())
	second := *cfg
	second.Port = port
	base := "http://127.0.0.1:" + port

	ctx, shutdown := context.WithCancel(context.WithoutCancel(t.Context()))
	defer shutdown()
	stopped := make(chan error, 1)
	go func() { stopped <- api.New(&second).Start(ctx) }()
	require.Eventually(t, func() bool {
		resp, err := http.Get(base + "/healthz")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 20*time.Millisecond, "the server never listened")

	// A daemon's control stream lives as long as the daemon. The deadline only matters when the shutdown misses it.
	streamCtx, giveUp := context.WithTimeout(t.Context(), 3*time.Second)
	defer giveUp()
	streamCtx, call := connect.NewClientContext(streamCtx)
	token := enrolled.GetAccessToken()
	call.RequestHeader().Set("Authorization", "DPoP "+token)
	call.RequestHeader().Set("DPoP", dpopProof(t, cfg, key, nokkuv1connect.DaemonControlServiceConnectProcedure, token))
	// A bidi stream needs HTTP/2, which a proxy speaks to the core without TLS.
	var h2c http.Protocols
	h2c.SetUnencryptedHTTP2(true)
	stream, err := nokkuv1connect.NewDaemonControlServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{Transport: &http.Transport{Protocols: &h2c}}, base))).
		Connect(streamCtx)
	require.NoError(t, err)
	defer func() { _ = stream.CloseSend() }()
	require.NoError(t, stream.Send(&nokkuv1.ConnectRequest{
		Msg: &nokkuv1.ConnectRequest_Heartbeat{Heartbeat: &nokkuv1.Heartbeat{}},
	}))

	// The body arrives after the shutdown began, so the handler runs inside the grace.
	body, send := io.Pipe()
	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodPost, base+nokkuv1connect.WorkspaceServiceGetWorkspaceProcedure, body,
	)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+member)
	status := make(chan int, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			status <- 0
			return
		}
		_ = resp.Body.Close()
		status <- resp.StatusCode
	}()
	time.Sleep(200 * time.Millisecond)
	shutdown()

	for {
		if _, err := stream.Receive(); err != nil {
			break
		}
	}
	require.NoError(t, streamCtx.Err(), "a stream outlived the root ctx")

	_, err = send.Write([]byte("{}"))
	require.NoError(t, err)
	require.NoError(t, send.Close())
	assert.Equal(t, http.StatusOK, <-status, "a request under way was cut by the shutdown")
	assert.NoError(t, <-stopped)
}

// The core only speaks plain HTTP. Its proxy forwards in h2c, and a client that connects by itself goes to https.
func TestPlainHTTPIsForTheProxy(t *testing.T) {
	cfg, _ := newTestAPI(t)
	named := *cfg
	named.BaseURL = "nokku.example.com"
	base := startCore(t, &named)

	var h2c http.Protocols
	h2c.SetUnencryptedHTTP2(true)
	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodPost, base+nokkuv1connect.UtilServiceGetVersionProcedure, strings.NewReader("{}"),
	)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := (&http.Client{Transport: &http.Transport{Protocols: &h2c}}).Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the proxy for a client on https is served")
	assert.Equal(t, 2, resp.ProtoMajor, "nk and nokkud speak gRPC through the proxy, that needs h2c")

	noFollow := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err = noFollow.Get(base + "/login?next=%2F")
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode, "a client that connects by itself is sent to https")
	assert.Equal(t, "https://nokku.example.com/login?next=%2F", resp.Header.Get("Location"))
}

// startCore runs the real server of cfg on a free port, the way the binary does, and returns its address.
func startCore(t *testing.T, cfg *config.Config) string {
	t.Helper()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(free.Addr().String())
	require.NoError(t, err)
	require.NoError(t, free.Close())
	cfg.Port = port
	base := "http://127.0.0.1:" + port

	ctx, stop := context.WithCancel(context.WithoutCancel(t.Context()))
	stopped := make(chan error, 1)
	go func() { stopped <- api.New(cfg).Start(ctx) }()
	t.Cleanup(func() {
		stop()
		assert.NoError(t, <-stopped)
	})
	require.Eventually(t, func() bool {
		resp, err := http.Get(base + "/healthz")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 20*time.Millisecond, "the server never listened")
	return base
}

// The owner's link is a way into the workspace, and a log line can travel to a telemetry backend.
func TestOwnerLinkStaysOutOfTheLog(t *testing.T) {
	var out logLines
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&out, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	cfg, _ := newTestAPI(t)
	fresh := *cfg
	fresh.OwnerNeedsLink = true
	startCore(t, &fresh)

	assert.Contains(t, out.String(), "run nokku admin-link")
	assert.NotContains(t, out.String(), "/login/verify")
}

// logLines collects what the server logs from its own goroutine.
type logLines struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logLines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logLines) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}
