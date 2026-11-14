package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
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
	"github.com/nokku-sh/nokku/daemon/internal/report"
	"github.com/nokku-sh/nokku/daemon/internal/sshd"
	"github.com/nokku-sh/nokku/daemon/internal/state"
	"github.com/nokku-sh/nokku/daemon/internal/sysutil"
)

const (
	dialTimeout   = 30 * time.Second
	enrollTimeout = 30 * time.Second
	// How long a busy core is retried. A rollout past its rate limit drains within minutes.
	enrollRetryFor = 5 * time.Minute
	syncTimeout    = 15 * time.Second
	// A full sync with nothing to trigger it. It is how the core hears of new accounts on the host, and how a
	// daemon knows that what it saved is still what the core says.
	resyncEvery = 4 * time.Hour
)

var (
	errDaemonRejected = errors.New("daemon rejected by core")

	enrollRetryFirst = 2 * time.Second
)

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
	// reports are the connections the core has yet to hear of.
	reports *report.Spool
	// One sync at a time, so an older answer never lands after a newer one.
	syncing sync.Mutex
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

	c := &Client{state: st, renew: make(chan struct{}, 1), reports: report.Open(paths.ReportsFile())}
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
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = enrollRetryFirst
	b.MaxInterval = time.Minute
	giveUp := time.Now().Add(enrollRetryFor)
	var res *nokkuv1.EnrollDaemonResponse
	for {
		callCtx, cancel := context.WithTimeout(ctx, enrollTimeout)
		// The hostname in the report may become the daemon's name.
		var err error
		res, err = c.ctl.EnrollDaemon(
			callCtx,
			&nokkuv1.EnrollDaemonRequest{Token: &token, Metadata: sysutil.Metadata()},
		)
		cancel()
		if err == nil {
			break
		}
		// The core's rate limit answers a bare 429, which reads as unavailable.
		code := connect.CodeOf(err)
		next := b.NextBackOff()
		if code != connect.CodeUnavailable && code != connect.CodeResourceExhausted ||
			time.Now().Add(next).After(giveUp) {
			return fmt.Errorf("enroll: %w", err)
		}
		slog.Warn("the core is busy, retrying the enrollment", "error", err, "retry_in", next.Round(time.Millisecond))
		select {
		case <-ctx.Done():
			return fmt.Errorf("enroll: %w", ctx.Err())
		case <-time.After(next):
		}
	}
	if res.GetTargetId() == "" || res.GetId() == "" || res.GetAccessToken() == "" {
		return errors.New("enroll: core returned an incomplete enrollment")
	}
	if err := sshd.CreateHostKey(); err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	c.state.TargetID = res.GetTargetId()
	c.state.DaemonID = res.GetId()
	c.state.SessionToken = res.GetAccessToken()
	// Re-enrolling may change Nokku, so nothing the old one trusted survives.
	c.state.SetAccess(&state.Access{DaemonConfig: res.GetConfig(), SyncedAt: time.Now()})
	return c.state.Save()
}

// Reports is where the SSH server puts its connections, the control stream sends them on.
func (c *Client) Reports() *report.Spool { return c.reports }

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
	go c.resync(ctx, resyncEvery)

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
		// A core that takes the stream says when to sync. One that refuses it has deleted this daemon or not
		// accepted it yet, and only a sync tells which.
		if code := connect.CodeOf(err); code != connect.CodeNotFound && code != connect.CodePermissionDenied {
			continue
		}
		if errors.Is(c.syncDaemon(ctx), errDaemonRejected) {
			return errDaemonRejected
		}
	}
}

// resync waits between half and one and a half of every, so a fleet that started together does not sync together.
func (c *Client) resync(ctx context.Context, every time.Duration) {
	for {
		wait := every/2 + rand.N(every) //nolint:gosec // spreads load, guards no secret
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		// A rejection drops the access here. The control stream ends the daemon on its next sync.
		if err := c.syncDaemon(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("periodic sync failed", "error", err)
		}
	}
}

func (c *Client) Unenroll(ctx context.Context) error {
	_, err := c.ctl.UnenrollDaemon(ctx, &nokkuv1.UnenrollDaemonRequest{})
	return err
}
