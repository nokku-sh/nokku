// Package dpopclient provides the DPoP-authenticated connect client stack
// shared by the Nokku binaries. It signs every RPC with a proof bound to the
// machine's signing key, carries the access token with the "DPoP" scheme,
// learns the server nonce and canonical API URL, and retries once when the
// server rejects a stale nonce.
package dpopclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/dpop"
)

const (
	// NonceRefreshAfter is how long a learned nonce is trusted before being
	// re-fetched ahead of a request.
	NonceRefreshAfter = 5 * time.Minute
	// APIURLHeader carries the canonical API URL the server binds proofs to,
	// which may differ from the configured one the request is sent to.
	APIURLHeader = "Nokku-Api-Url"
)

// Options configures a Client.
type Options struct {
	// BaseURL is the configured API URL, used until the server advertises a
	// canonical one. Required for nonce prefetch and proof binding.
	BaseURL string
	// UnboundProcedures are signed with an unbound proof (no token, no ath)
	// when no access token exists yet, such as enrollment.
	UnboundProcedures map[string]bool
	// UserAgent, when non-empty, is set on every request.
	UserAgent string
}

// Client is a connect interceptor that authenticates requests with a
// DPoP-bound access token. It is safe for concurrent use.
type Client struct {
	proofer *dpop.Proofer
	httpc   *http.Client
	token   func() string
	base    string
	unbound map[string]bool
	ua      string

	mu        sync.Mutex
	nonce     string
	learnedAt time.Time
	serverURL string
}

// New builds a client. proofer signs the proofs. token returns the current
// access token, or "" before enrollment and for service-account calls, which
// are left unauthenticated here and signed by the caller's own interceptor.
func New(
	proofer *dpop.Proofer,
	httpc *http.Client,
	token func() string,
	opts Options,
) *Client {
	return &Client{
		proofer: proofer,
		httpc:   httpc,
		token:   token,
		base:    opts.BaseURL,
		unbound: opts.UnboundProcedures,
		ua:      opts.UserAgent,
	}
}

// NewHTTPClient builds the HTTP/2-only, TLS 1.3 minimum client the control
// plane expects. roots is what the server certificate is verified against,
// nil means the system roots. See the trust package for a server behind a
// private CA. dialTimeout bounds connection setup.
func NewHTTPClient(roots *x509.CertPool, dialTimeout time.Duration) (*http.Client, error) {
	proto := new(http.Protocols)
	proto.SetHTTP1(false)
	proto.SetHTTP2(true)
	proto.SetUnencryptedHTTP2(true)

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("dpopclient: expected *http.Transport as default transport")
	}
	t := base.Clone()
	t.Protocols = proto
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	t.DialContext = (&net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
	}).DialContext
	return &http.Client{Transport: t}, nil
}

// FetchNonce bootstraps the DPoP nonce and the canonical API URL before the
// first protected request, avoiding a deliberate 401 round-trip. baseURL is
// only where to reach the server. The canonical URL is what proofs bind to.
func FetchNonce(
	ctx context.Context,
	httpc *http.Client,
	baseURL string,
) (nonce, apiURL string, err error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		strings.TrimRight(baseURL, "/")+"/auth/device/nonce",
		nil,
	)
	if err != nil {
		return "", "", err
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.Header.Get("DPoP-Nonce"), resp.Header.Get(APIURLHeader), nil
}

// WrapUnary signs the request, and retries once when the server rejects the
// proof with a stale nonce that came with a fresh one.
func (c *Client) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		c.refreshNonce(ctx)
		if err := c.sign(req.Header(), req.Spec().Procedure); err != nil {
			return nil, err
		}

		resp, err := next(ctx, req)
		if err != nil && c.LearnFromError(err) {
			// Wipe the rejected proof before signing again.
			req.Header().Del("DPoP")
			if err = c.sign(req.Header(), req.Spec().Procedure); err != nil {
				return nil, err
			}
			return next(ctx, req)
		}
		return resp, err
	}
}

// WrapStreamingClient signs the stream once and cannot retry: a stale-nonce
// rejection tears the stream down before the first message lands, surfacing
// as an opaque write failure.
func (c *Client) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		c.refreshNonce(ctx)
		conn := next(ctx, spec)
		if err := c.sign(conn.RequestHeader(), spec.Procedure); err != nil {
			// The stream fails at the server, this keeps the reason.
			slog.Warn("dpop: sign stream request", "procedure", spec.Procedure, "error", err)
		}
		return conn
	}
}

// WrapStreamingHandler passes through, this is a client-side interceptor.
func (c *Client) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return next
}

// Proof signs a DPoP proof for htm/htu, carrying the ath claim when an access
// token exists. Device-flow endpoints call it directly for raw HTTP requests.
func (c *Client) Proof(htm, htu string) (string, error) {
	ath := ""
	if token := c.token(); token != "" {
		ath = dpop.ATH(token)
	}
	return c.proofer.Sign(htm, htu, ath, c.currentNonce())
}

// HtuBase returns the URL proofs must bind to: the canonical API URL the
// server advertised when known, else the configured one.
func (c *Client) HtuBase() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.serverURL != "" {
		return c.serverURL
	}
	return c.base
}

// Learn records a nonce and canonical URL fetched out of band via FetchNonce.
// A learned nonce counts as fresh, so the next request skips the prefetch.
func (c *Client) Learn(nonce, serverURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if nonce != "" {
		c.nonce = nonce
		c.learnedAt = time.Now()
	}
	if serverURL != "" {
		c.serverURL = serverURL
	}
}

// LearnHeaders records the nonce and canonical URL a raw HTTP response
// advertised.
func (c *Client) LearnHeaders(h http.Header) {
	c.Learn(h.Get("DPoP-Nonce"), h.Get(APIURLHeader))
}

// LearnFromError records a fresh nonce from a stale-nonce error response and
// reports whether the server advertised one, so the caller retries once.
func (c *Client) LearnFromError(err error) bool {
	cerr, ok := errors.AsType[*connect.Error](err)
	if !ok || connect.CodeOf(err) != connect.CodeUnauthenticated {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	learned := false
	if n := cerr.Meta().Get("DPoP-Nonce"); n != "" {
		c.nonce = n
		c.learnedAt = time.Now()
		learned = true
	}
	if u := cerr.Meta().Get(APIURLHeader); u != "" {
		c.serverURL = u
	}
	return learned
}

// sign sets the User-Agent, the bound token, and the DPoP proof on a request.
// Without a token only procedures marked unbound are signed.
func (c *Client) sign(header http.Header, procedure string) error {
	if c.ua != "" {
		header.Set("User-Agent", c.ua)
	}
	token := c.token()
	if token == "" && !c.unbound[procedure] {
		return nil
	}
	if token != "" {
		// RFC 9449: MUST use the "DPoP" scheme for bound tokens.
		header.Set("Authorization", "DPoP "+token)
	}
	proof, err := c.Proof(http.MethodPost, c.HtuBase()+procedure)
	if err != nil {
		return connect.NewError(
			connect.CodeInternal,
			fmt.Errorf("failed to sign DPoP proof: %w", err),
		)
	}
	header.Set("DPoP", proof)
	return nil
}

// refreshNonce prefetches the server nonce when the cached one is old enough
// to risk rejection. Best effort: on failure the cached nonce is kept.
func (c *Client) refreshNonce(ctx context.Context) {
	c.mu.Lock()
	learnedAt := c.learnedAt
	c.mu.Unlock()
	if time.Since(learnedAt) <= NonceRefreshAfter {
		return
	}
	nonce, serverURL, err := FetchNonce(ctx, c.httpc, c.base)
	if err != nil {
		slog.Debug("dpop nonce prefetch failed, using cached nonce", "error", err)
		return
	}
	c.Learn(nonce, serverURL)
}

func (c *Client) currentNonce() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nonce
}
