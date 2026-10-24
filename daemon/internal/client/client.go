package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"time"

	"connectrpc.com/connect"
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
	dialTimeout       = 30 * time.Second
	enrollTimeout     = 30 * time.Second
	syncTimeout       = 15 * time.Second
	retryUploadsEvery = 5 * time.Minute
	// A full workspace refuses every upload, and each one is a failed call in its audit log.
	retryUploadsWhenFull = time.Hour
)

var errDaemonRejected = errors.New("daemon rejected by core")

type Client struct {
	cache  *state.Cache
	config *state.Config
	dpop   *dpopclient.Client
	ctl    nokkuv1connect.DaemonControlServiceClient

	// Set by Run before any goroutine starts.
	srv     *sshd.Server
	sshAddr netip.AddrPort
	relays  sync.WaitGroup

	// renew wakes the certificate watcher when the trusted CA changed.
	renew chan struct{}
}

func New(
	ctx context.Context,
	cache *state.Cache,
	config *state.Config,
	requireTPM bool,
	enrollToken string,
) (*Client, error) {
	roots, err := trust.Pool([]byte(config.APICA))
	if err != nil {
		return nil, err
	}
	httpc, err := dpopclient.NewHTTPClient(roots, dialTimeout)
	if err != nil {
		return nil, err
	}
	// The identity is bound to the enrollment, so only a new enrollment may recreate it.
	proofer, err := dpopclient.NewProofer(tpm.SignerOptions{
		StatePath:  paths.SignerStateFile(),
		RequireTPM: requireTPM,
		Recreate:   enrollToken != "",
	})
	if err != nil {
		return nil, err
	}

	c := &Client{cache: cache, config: config, renew: make(chan struct{}, 1)}
	apiURL := config.APIURL
	c.dpop = dpopclient.New(proofer, httpc, func() string { return config.SessionToken }, dpopclient.Options{
		BaseURL:           apiURL,
		UnboundProcedures: map[string]bool{nokkuv1connect.DaemonControlServiceEnrollDaemonProcedure: true},
		UserAgent:         buildinfo.UserAgent("nokkud"),
	})
	c.ctl = nokkuv1connect.NewDaemonControlServiceClient(httpc, apiURL, connect.WithInterceptors(c.dpop))

	if enrollToken != "" {
		if err = c.enroll(ctx, enrollToken); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// The DPoP proof is unbound, the server binds the issued session to the daemon's key.
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
	// A re-enrollment may move the host to another Nokku, so nothing the old one trusted may survive.
	c.cache.Clear()
	if err = os.Remove(paths.HostKeyCert()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("enroll: drop previous host certificate: %w", err)
	}
	c.config.TargetID = res.GetTargetId()
	c.config.DaemonID = res.GetId()
	c.config.SessionToken = res.GetAccessToken()
	c.cache.SetDaemonConfig(res.GetConfig())
	if err = c.config.Save(); err != nil {
		return err
	}
	return c.cache.Save()
}

func (c *Client) RecordingSink(ctx context.Context, sessionID, username, principal string) io.WriteCloser {
	return recording.NewUploader(ctx, c.ctl, sessionID, username, principal)
}

func (c *Client) retryUploads(ctx context.Context) {
	for {
		err := recording.UploadPending(ctx, c.ctl)
		if err != nil {
			slog.Debug("recording upload retry failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(uploadRetryWait(err)):
		}
	}
}

func uploadRetryWait(err error) time.Duration {
	if connect.CodeOf(err) == connect.CodeResourceExhausted {
		return retryUploadsWhenFull
	}
	return retryUploadsEvery
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
	go c.retryUploads(ctx)

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
		// A rejected stream may carry a fresh DPoP nonce for the next dial.
		c.dpop.LearnFromError(err)

		// Connect returns before the core answers, so only a stream that stayed up proves it was reachable.
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
		// A daemon deleted while offline gets no stream and no poke, only a sync tells it to stop.
		if errors.Is(c.syncDaemon(ctx), errDaemonRejected) {
			return errDaemonRejected
		}
	}
}

func (c *Client) Unenroll(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, err := c.ctl.UnenrollDaemon(ctx, &nokkuv1.UnenrollDaemonRequest{})
	return err
}
