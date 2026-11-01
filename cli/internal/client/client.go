package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/fsutil"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/cli/internal/ssh"
	"github.com/nokku-sh/nokku/cli/internal/state"
	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokku/internal/dpop"
	"github.com/nokku-sh/nokku/internal/dpopclient"
	"github.com/nokku-sh/nokku/internal/tpm"
	"github.com/nokku-sh/nokku/internal/trust"
)

const (
	syncTimeout = 5 * time.Second
	dialTimeout = 3 * time.Second
)

type Client struct {
	State   *state.State
	httpc   *http.Client
	proofer *dpop.Proofer
	dpop    *dpopclient.Client

	auth            nokkuv1connect.AuthServiceClient
	certs           nokkuv1connect.CertificateServiceClient
	targets         nokkuv1connect.TargetServiceClient
	daemons         nokkuv1connect.DaemonServiceClient
	users           nokkuv1connect.WorkspaceServiceClient
	teams           nokkuv1connect.TeamServiceClient
	serviceAccounts nokkuv1connect.ServiceAccountServiceClient
	requests        nokkuv1connect.AccessRequestServiceClient
}

func New(s *state.State) (*Client, error) {
	c := &Client{State: s}
	if !s.IsServiceAccount() {
		proofer, err := dpopclient.NewProofer(tpm.SignerOptions{
			StatePath:  paths.SignerStateFile(),
			RequireTPM: s.RequireTPM,
			Recreate:   true,
		})
		if err != nil {
			return nil, err
		}
		c.proofer = proofer
	}
	return c, c.dial()
}

func (c *Client) dial() error {
	s := c.State
	roots, err := trust.Pool([]byte(s.APICA))
	if err != nil {
		return err
	}
	c.httpc, err = dpopclient.NewHTTPClient(roots, dialTimeout)
	if err != nil {
		return err
	}

	auth := (&bearerAuth{token: s.Token, ua: buildinfo.UserAgent("nk")}).intercept
	if c.proofer != nil {
		c.dpop = dpopclient.New(c.proofer, c.httpc, func() string { return s.SessionToken }, dpopclient.Options{
			BaseURL:           s.APIURL,
			UnboundProcedures: map[string]bool{nokkuv1connect.AuthServiceExchangeWorkloadTokenProcedure: true},
			UserAgent:         buildinfo.UserAgent("nk"),
		})
		auth = c.dpop.Intercept
	}
	// Unbounded, the access snapshot and target pages grow with the workspace.
	cc := connect.NewClient(
		connecthttp.NewTransport(c.httpc, s.APIURL, connecthttp.WithReadMaxBytes(0)),
		callTimeout,
		auth,
	)
	c.auth = nokkuv1connect.NewAuthServiceClient(cc)
	c.certs = nokkuv1connect.NewCertificateServiceClient(cc)
	c.targets = nokkuv1connect.NewTargetServiceClient(cc)
	c.daemons = nokkuv1connect.NewDaemonServiceClient(cc)
	c.users = nokkuv1connect.NewWorkspaceServiceClient(cc)
	c.teams = nokkuv1connect.NewTeamServiceClient(cc)
	c.serviceAccounts = nokkuv1connect.NewServiceAccountServiceClient(cc)
	c.requests = nokkuv1connect.NewAccessRequestServiceClient(cc)
	return nil
}

// Sync without interactive fails instead of opening a browser.
func (c *Client) Sync(ctx context.Context, interactive bool) error {
	err := c.sync(ctx, interactive)
	if trust.Untrusted(err) {
		return fmt.Errorf("this machine does not trust the certificate of %s. "+
			"If it comes from a private CA, pass that CA with --ca-file: %w", c.State.APIURL, err)
	}
	if err == nil || connect.CodeOf(err) != connect.CodeUnauthenticated {
		return err
	}
	if c.State.CIJob() {
		return ErrCISessionEnded
	}
	if !interactive {
		return err
	}
	c.State.SessionToken, c.State.SessionExpiresAt = "", time.Time{}
	if err = c.ensureSession(ctx, true); err != nil {
		return err
	}
	return c.sync(ctx, false)
}

// SyncOrCache keeps ssh working on the cached snapshot while the core is down.
func (c *Client) SyncOrCache(ctx context.Context, interactive bool) error {
	err := c.Sync(ctx, interactive)
	if err == nil {
		return nil
	}
	// No outage. Going on from the cache would only fail later, less clearly.
	if errors.Is(err, ErrCISessionEnded) {
		return err
	}
	if loadErr := c.State.LoadCache(); loadErr != nil || !c.State.HasCachedData() {
		return fmt.Errorf("sync with Nokku failed and nothing is cached yet: %w", err)
	}
	slog.Warn("sync with Nokku failed, using cached access", "err", err)
	c.State.MarkSyncFailed()
	return nil
}

func (c *Client) sync(ctx context.Context, interactive bool) error {
	if err := c.ensureSession(ctx, interactive); err != nil {
		return err
	}
	res, err := c.targets.GetSubjectAccess(ctx, &nokkuv1.GetSubjectAccessRequest{})
	if err != nil {
		return err
	}

	cache := state.FromAccess(res)
	cache.Server = c.State.APIURL
	cache.SyncedAt = time.Now()
	keep := cache.Targets
	if id := cache.SubjectID(); id == "" || id != c.State.SubjectID() {
		// A certificate names its subject, so another login must not use it.
		keep = nil
	}
	if err = ssh.CleanupCerts(keep); err != nil {
		return err
	}
	c.State.Cache = cache
	if err = c.State.Save(); err != nil {
		return err
	}
	return ssh.WriteConfigs(c.State)
}

// Logout revokes the session. The caller removes local state either way.
func (c *Client) Logout(ctx context.Context) error {
	if c.State.IsServiceAccount() || c.State.SessionToken == "" {
		return nil
	}
	_, err := c.auth.Logout(ctx, &nokkuv1.LogoutRequest{})
	return err
}

// EnsureCert keeps the old certificate if signing fails, for offline ssh.
func (c *Client) EnsureCert(ctx context.Context, target state.Target, ca state.CA) error {
	if ssh.CertFresh(target, ca) {
		return nil
	}
	if err := c.ensureSession(ctx, false); err != nil {
		return err
	}
	pubKey, err := ssh.PubKey()
	if err != nil {
		return err
	}

	req := &nokkuv1.SignSSHCertificateRequest{
		TargetId:  new(target.ID),
		PublicKey: new(pubKey),
	}
	if c.State.TTL > 0 {
		req.Ttl = durationpb.New(c.State.TTL)
	}
	res, err := c.certs.SignSSHCertificate(ctx, req)
	if c.State.CIJob() && connect.CodeOf(err) == connect.CodeUnauthenticated {
		return ErrCISessionEnded
	}
	if err != nil {
		return err
	}

	signed := []byte(res.GetSignedCertificate())
	if err = ssh.CheckCert(signed, ca.PublicKey, 0); err != nil {
		return fmt.Errorf("core returned an unusable certificate: %w", err)
	}
	return fsutil.WriteFile(paths.SSHCertificate(target.ID), signed, 0o600)
}

// ReportTarget also stamps the target's last sync.
func (c *Client) ReportTarget(ctx context.Context, t *state.Target, accounts []string, hostKey string) error {
	_, err := c.targets.SyncTargetUsers(ctx, &nokkuv1.SyncTargetUsersRequest{
		TargetId:      new(t.ID),
		Usernames:     accounts,
		HostPublicKey: new(hostKey),
		Endpoints:     t.Endpoints,
	})
	return err
}

// CreateTarget with an empty name lets the server generate one.
func (c *Client) CreateTarget(
	ctx context.Context,
	t *state.Target,
	tags []string,
	grants []Grant,
) (*state.Target, error) {
	req := &nokkuv1.CreateTargetRequest{
		Name:          new(t.Name),
		HostPublicKey: new(t.HostPublicKey),
		Endpoints:     t.Endpoints,
		Tags:          tags,
	}
	for _, g := range grants {
		req.Grants = append(req.Grants, &nokkuv1.JoinTokenGrant{
			Username:          new(g.Account),
			UserIds:           g.Users,
			TeamIds:           g.Teams,
			ServiceAccountIds: g.ServiceAccounts,
		})
	}
	res, err := c.targets.CreateTarget(ctx, req)
	if err != nil {
		return nil, err
	}
	created := state.MapTarget(res.GetTarget())
	return &created, nil
}

func (c *Client) DeleteTarget(ctx context.Context, t *state.Target) error {
	_, err := c.targets.DeleteTarget(ctx, &nokkuv1.DeleteTargetRequest{
		Id: new(t.ID),
	})
	return err
}

// ListAllTargets also has targets the subject can't log in to.
func (c *Client) ListAllTargets(ctx context.Context) ([]state.Target, error) {
	var out []state.Target
	for offset := int32(0); ; offset += lookupLimit {
		res, err := c.targets.ListTargets(ctx, &nokkuv1.ListTargetsRequest{
			Limit:  new(int32(lookupLimit)),
			Offset: new(offset),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, state.Targets(res.GetTargets())...)
		if n := len(res.GetTargets()); n < lookupLimit || int(offset)+n >= int(res.GetTotal()) {
			return out, nil
		}
	}
}

// WorkspaceCA asks the core and not the cache, so nk sync sees a rollover.
func (c *Client) WorkspaceCA(ctx context.Context) (*state.CA, error) {
	res, err := c.certs.GetCertificateAuthority(ctx, &nokkuv1.GetCertificateAuthorityRequest{})
	if err != nil {
		return nil, err
	}
	return state.MapCA(res.GetCertificateAuthority()), nil
}
