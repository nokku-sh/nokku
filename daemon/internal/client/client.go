package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/cenkalti/backoff/v7"
	"github.com/mizuchilabs/kata/buildinfo"

	"github.com/nokku-sh/nokku/internal/dpopclient"
	"github.com/nokku-sh/nokku/internal/tpm"
	"github.com/nokku-sh/nokku/internal/trust"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	nokkuv1connect "github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
	"github.com/nokku-sh/nokku/daemon/internal/recording"
	"github.com/nokku-sh/nokku/daemon/internal/sshd"
	"github.com/nokku-sh/nokku/daemon/internal/state"
	"github.com/nokku-sh/nokku/daemon/internal/sysutil"
)

const (
	dialTimeout   = 30 * time.Second
	enrollTimeout = 30 * time.Second
	syncTimeout   = 15 * time.Second
)

var errDaemonRejected = errors.New("daemon rejected by core")

type Client struct {
	state *state.State
	dpop  *dpopclient.Client
	ctl   nokkuv1connect.DaemonControlServiceClient

	// Set by Run before any goroutine starts.
	srv     *sshd.Server
	sshAddr netip.AddrPort
	relays  sync.WaitGroup

	// renew wakes the certificate watcher when the trusted CA changed.
	renew chan struct{}
}

func New(ctx context.Context, st *state.State, requireTPM bool, enrollToken string) (*Client, error) {
	roots, err := trust.Pool([]byte(st.APICA))
	if err != nil {
		return nil, err
	}
	httpc, err := dpopclient.NewHTTPClient(roots, dialTimeout)
	if err != nil {
		return nil, err
	}
	// The identity is bound to the enrollment, only a new one may recreate it.
	proofer, err := dpopclient.NewProofer(tpm.SignerOptions{
		StatePath:  paths.SignerStateFile(),
		RequireTPM: requireTPM,
		Recreate:   enrollToken != "",
	})
	if err != nil {
		return nil, err
	}

	c := &Client{state: st, renew: make(chan struct{}, 1)}
	apiURL := st.APIURL
	c.dpop = dpopclient.New(proofer, httpc, func() string { return st.SessionToken }, dpopclient.Options{
		BaseURL:           apiURL,
		UnboundProcedures: map[string]bool{nokkuv1connect.DaemonControlServiceEnrollDaemonProcedure: true},
		UserAgent:         buildinfo.UserAgent("nokkud"),
	})
	// Unbounded, a sync carries every principal of the workspace.
	transport := connecthttp.NewTransport(httpc, apiURL, connecthttp.WithReadMaxBytes(0))
	c.ctl = nokkuv1connect.NewDaemonControlServiceClient(connect.NewClient(transport, c.dpop.Intercept))

	if enrollToken != "" {
		if err = c.enroll(ctx, enrollToken); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// The proof is unbound, the server binds the new session to the daemon's key.
func (c *Client) enroll(ctx context.Context, token string) error {
	ctx, cancel := context.WithTimeout(ctx, enrollTimeout)
	defer cancel()
	// The hostname in the report may become the daemon's name.
	res, err := c.ctl.EnrollDaemon(ctx, &nokkuv1.EnrollDaemonRequest{Token: &token, Metadata: sysutil.Metadata()})
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if res.GetTargetId() == "" || res.GetId() == "" || res.GetAccessToken() == "" {
		return errors.New("enroll: core returned an incomplete enrollment")
	}
	if err = sshd.CreateHostKey(); err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	c.state.TargetID = res.GetTargetId()
	c.state.DaemonID = res.GetId()
	c.state.SessionToken = res.GetAccessToken()
	// Re-enrolling may change Nokku, so nothing the old one trusted survives.
	c.state.SetAccess(&state.Access{DaemonConfig: res.GetConfig()})
	return c.state.Save()
}

func (c *Client) StartUploads(ctx context.Context) *recording.Uploads {
	return recording.NewUploads(ctx, c.ctl)
}

func (c *Client) Run(ctx context.Context, srv *sshd.Server, sshAddr netip.AddrPort) error {
	c.srv = srv
	c.sshAddr = sshAddr
	// Deferred in this order so relays are canceled before they are joined.
	defer c.relays.Wait()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	err := c.syncDaemon(ctx)
	if errors.Is(err, errDaemonRejected) {
		return err
	}
	if err != nil {
		slog.Warn("initial sync failed, serving from cache", "error", err)
	}
	go c.watchCertificates(ctx)

	b := backoff.NewExponentialBackOff()
	b.InitialInterval = time.Second
	b.MaxInterval = time.Minute
	warned := false
	for {
		start := time.Now()
		err = c.runControlStream(ctx)
		if errors.Is(err, errDaemonRejected) {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		// Connect returns before the core answers, so judge it by uptime.
		if time.Since(start) > 2*heartbeatInterval {
			b.Reset()
			warned = false
		}
		next := b.NextBackOff()
		if !warned {
			slog.Warn("control stream down, retrying in background", "error", err)
			warned = true
		} else {
			slog.Debug("control stream retry failed", "error", err, "retry_in", next.Round(time.Millisecond))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(next):
		}
		// Deleted while offline means no poke, only a sync tells it to stop.
		if errors.Is(c.syncDaemon(ctx), errDaemonRejected) {
			return errDaemonRejected
		}
	}
}

func (c *Client) Unenroll(ctx context.Context) error {
	_, err := c.ctl.UnenrollDaemon(ctx, &nokkuv1.UnenrollDaemonRequest{})
	return err
}
