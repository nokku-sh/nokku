package client

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"

	"connectrpc.com/connect/v2"
	"github.com/mizuchilabs/kata/buildinfo"
	"github.com/mizuchilabs/kata/fsutil"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/nokku-sh/nokku/cli/internal/enclave"
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
			Enclave:    enclave.New(),
		})
		if err != nil {
			return nil, err
		}
		c.proofer = proofer
	}
	return c, c.dial()
}

// Runs again when the CA the API is trusted through changed.
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

	var auth connect.Interceptor = &bearerAuth{token: s.Token, ua: buildinfo.UserAgent("nk")}
	if c.proofer != nil {
		c.dpop = dpopclient.New(c.proofer, c.httpc, func() string { return s.SessionToken }, dpopclient.Options{
			BaseURL:   s.APIURL,
			UserAgent: buildinfo.UserAgent("nk"),
		})
		auth = c.dpop
	}
	opts := connect.WithInterceptors(callTimeout, auth)
	c.auth = nokkuv1connect.NewAuthServiceClient(c.httpc, s.APIURL, opts)
	c.certs = nokkuv1connect.NewCertificateServiceClient(c.httpc, s.APIURL, opts)
	c.targets = nokkuv1connect.NewTargetServiceClient(c.httpc, s.APIURL, opts)
	c.daemons = nokkuv1connect.NewDaemonServiceClient(c.httpc, s.APIURL, opts)
	c.users = nokkuv1connect.NewWorkspaceServiceClient(c.httpc, s.APIURL, opts)
	c.teams = nokkuv1connect.NewTeamServiceClient(c.httpc, s.APIURL, opts)
	c.serviceAccounts = nokkuv1connect.NewServiceAccountServiceClient(c.httpc, s.APIURL, opts)
	c.requests = nokkuv1connect.NewAccessRequestServiceClient(c.httpc, s.APIURL, opts)
	return nil
}

// Sync without interactive takes a missing or rejected session as an error instead of a browser login.
func (c *Client) Sync(ctx context.Context, interactive bool) error {
	if err := c.pinServer(ctx); err != nil {
		return err
	}
	err := c.sync(ctx, interactive)
	if trust.Untrusted(err) {
		if err = c.confirmServer(ctx, interactive, err); err != nil {
			return err
		}
		err = c.sync(ctx, interactive)
	}
	if err == nil || !interactive || connect.CodeOf(err) != connect.CodeUnauthenticated {
		return err
	}
	// The stored session was rejected, log in once more.
	c.State.SessionToken, c.State.SessionExpiresAt = "", time.Time{}
	if err = c.ensureSession(ctx, true); err != nil {
		return err
	}
	return c.sync(ctx, false)
}

// SyncOrCache falls back to the cached snapshot, so ssh keeps working while the core is down.
func (c *Client) SyncOrCache(ctx context.Context, interactive bool) error {
	err := c.Sync(ctx, interactive)
	if err == nil {
		return nil
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
	res, err := c.targets.GetMyAccess(ctx, &nokkuv1.GetMyAccessRequest{})
	if err != nil {
		return err
	}

	cache := state.FromAccess(res)
	cache.Server = c.State.APIURL
	cache.SyncedAt = time.Now()
	keep := cache.Targets
	if id := cache.SubjectID(); id == "" || id != c.State.SubjectID() {
		// A certificate names its subject. One signed in as someone else must not use it.
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

// Logout revokes the session on the core. The caller removes the local state either way.
func (c *Client) Logout(ctx context.Context) error {
	if c.State.IsServiceAccount() || c.State.SessionToken == "" {
		return nil
	}
	_, err := c.auth.Logout(ctx, &nokkuv1.LogoutRequest{})
	return err
}

// EnsureCert keeps the certificate on disk when signing fails, so ssh works offline while it is valid.
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
	if err != nil {
		return err
	}

	signed := []byte(res.GetSignedCertificate())
	if err = ssh.CheckCert(signed, ca.PublicKey, 0); err != nil {
		return fmt.Errorf("core returned an unusable certificate: %w", err)
	}
	return fsutil.WriteFile(paths.SSHCertificate(target.ID), signed, 0o600)
}

// TargetPrincipals come from the core as they are, sshd compares them as whole strings.
func (c *Client) TargetPrincipals(ctx context.Context, t *state.Target) (map[string][]string, error) {
	res, err := c.targets.GetTargetPrincipals(ctx, &nokkuv1.GetTargetPrincipalsRequest{
		TargetId: new(t.ID),
	})
	if err != nil {
		return nil, err
	}
	grants := make(map[string][]string, len(res.GetPrincipals()))
	for _, p := range res.GetPrincipals() {
		if i := slices.IndexFunc(p.GetCertPrincipals(), unsafePrincipal); i >= 0 {
			return nil, fmt.Errorf(
				"the core sent an unusable principal %q, nothing was written",
				p.GetCertPrincipals()[i],
			)
		}
		grants[p.GetUsername()] = p.GetCertPrincipals()
	}
	return grants, nil
}

// unsafePrincipal would not stay one name on one line. sshd reads what follows a space as options, like command=.
func unsafePrincipal(p string) bool {
	return p == "" || strings.ContainsFunc(p, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || r == '"' || r == '\''
	})
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

// CreateTarget with an empty name asks the server to generate one. The grants are seeded with it, once.
func (c *Client) CreateTarget(
	ctx context.Context,
	t *state.Target,
	tags []string,
	grants []Grant,
) (*state.Target, error) {
	req := &nokkuv1.CreateTargetRequest{
		CaId:          new(t.CAID),
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
	created.CAID = t.CAID
	return &created, nil
}

func (c *Client) DeleteTarget(ctx context.Context, t *state.Target) error {
	_, err := c.targets.DeleteTarget(ctx, &nokkuv1.DeleteTargetRequest{
		Id: new(t.ID),
	})
	return err
}

// ListAllTargets is for nk sync and rm. The access sync only carries the targets the subject may log in to.
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

// ListSSHCAs is for a new target, the access sync only carries the CAs of targets the subject can reach.
func (c *Client) ListSSHCAs(ctx context.Context) ([]state.CA, error) {
	res, err := c.certs.ListCertificateAuthorities(ctx, &nokkuv1.ListCertificateAuthoritiesRequest{})
	if err != nil {
		return nil, err
	}
	active := slices.DeleteFunc(res.GetCertificateAuthorities(), func(ca *nokkuv1.CertificateAuthority) bool {
		return !ca.GetIsActive()
	})
	return state.SSHCAs(active), nil
}
