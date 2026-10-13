// Package dpopclient provides the DPoP-authenticated connect client stack
// shared by the Nokku binaries. It signs every RPC with a proof bound to the
// machine's signing key, carries the access token with the "DPoP" scheme,
// learns the server nonce, and retries once when the server rejects a stale
// nonce. Proofs bind to the configured API URL and nothing else.
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
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/dpop"
)

const (
	// The server keeps a nonce valid for 5 minutes at least.
	nonceRefreshAfter = 4 * time.Minute
	nonceRetryAfter   = 30 * time.Second
	nonceFetchTimeout = 10 * time.Second
	apiURLHeader      = "Nokku-Api-Url"
)

// ErrAPIURLMismatch signals that the server lives at another URL than the
// configured one. Proofs only verify for the URL the server knows itself by,
// so the caller has to be pointed at that URL.
var ErrAPIURLMismatch = errors.New("dpopclient: the server is not at the configured API URL")

// Options configures a Client.
type Options struct {
	// BaseURL is the configured API URL. Requests go there and proofs bind to
	// it, so it must be the URL the server knows itself by.
	BaseURL string
	// UnboundProcedures are always signed with an unbound proof (no token, no
	// ath), such as enrollment. A stored token is never sent to them.
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
	triedAt   time.Time
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
		base:    strings.TrimRight(opts.BaseURL, "/"),
		unbound: opts.UnboundProcedures,
		ua:      opts.UserAgent,
	}
}

// NewHTTPClient builds the HTTP/2-only, TLS 1.3 minimum client the control
// plane expects. roots is what the server certificate is verified against,
// nil means the system roots. See the trust package for a server behind a
// private CA. dialTimeout bounds connection setup. Redirects are not followed,
// a proof is only valid for the URL it was signed for.
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
	return &http.Client{
		Transport:     t,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// FetchNonce bootstraps the DPoP nonce before the first protected request,
// avoiding a deliberate 401 round-trip. It fails with [ErrAPIURLMismatch] when
// the server says it lives at another URL than baseURL.
func FetchNonce(ctx context.Context, httpc *http.Client, baseURL string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, nonceFetchTimeout)
	defer cancel()

	baseURL = strings.TrimRight(baseURL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/auth/device/nonce", nil)
	if err != nil {
		return "", err
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if advertised := resp.Header.Get(apiURLHeader); advertised != "" && !sameURL(advertised, baseURL) {
		return "", fmt.Errorf("%w: %s says it is at %q, use that URL", ErrAPIURLMismatch, baseURL, advertised)
	}
	return resp.Header.Get("DPoP-Nonce"), nil
}

// WrapUnary signs the request, and retries once when the server rejects the
// proof with a stale nonce that came with a fresh one.
func (c *Client) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if err := c.sign(ctx, req.Header(), req.Spec().Procedure); err != nil {
			return nil, err
		}

		resp, err := next(ctx, req)
		if err != nil && c.LearnFromError(err) {
			// Wipe the rejected proof before signing again.
			req.Header().Del("DPoP")
			if err = c.sign(ctx, req.Header(), req.Spec().Procedure); err != nil {
				return nil, err
			}
			return next(ctx, req)
		}
		return resp, err
	}
}

// WrapStreamingClient signs the stream once and cannot retry: a stale-nonce
// rejection tears the stream down before the first message lands, surfacing
// as an opaque write failure. A stream that cannot be signed is never sent,
// its first Send or Receive returns the reason.
func (c *Client) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		if err := c.sign(ctx, conn.RequestHeader(), spec.Procedure); err != nil {
			return &failedConn{StreamingClientConn: conn, err: err}
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

// Proof signs a DPoP proof for a request to urlPath on the configured API
// URL, carrying the ath claim when an access token exists. Like every signed
// request it fetches a nonce first when the cached one is old, and fails with
// [ErrAPIURLMismatch] when the server lives at another URL. Device-flow
// endpoints call it directly for raw HTTP requests.
func (c *Client) Proof(ctx context.Context, method, urlPath string) (string, error) {
	if err := c.refreshNonce(ctx); err != nil {
		return "", err
	}
	return c.proof(method, urlPath, c.token())
}

// Learn records a nonce taken from a raw HTTP response. A learned nonce
// counts as fresh, so the next proof skips the prefetch.
func (c *Client) Learn(nonce string) {
	if nonce == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nonce = nonce
	c.learnedAt = time.Now()
}

// LearnFromError records a fresh nonce from a stale-nonce error response and
// reports whether the server advertised one, so the caller retries once.
func (c *Client) LearnFromError(err error) bool {
	cerr, ok := errors.AsType[*connect.Error](err)
	if !ok || connect.CodeOf(err) != connect.CodeUnauthenticated {
		return false
	}
	nonce := cerr.Meta().Get("DPoP-Nonce")
	c.Learn(nonce)
	return nonce != ""
}

// Without a token only procedures marked unbound are signed.
func (c *Client) sign(ctx context.Context, header http.Header, procedure string) error {
	if c.ua != "" {
		header.Set("User-Agent", c.ua)
	}
	token := c.token()
	if c.unbound[procedure] {
		// An enrollment may go to another server than the one the stored token came from.
		token = ""
	} else if token == "" {
		return nil
	}
	if err := c.refreshNonce(ctx); err != nil {
		return err
	}
	proof, err := c.proof(http.MethodPost, procedure, token)
	if err != nil {
		return connect.NewError(
			connect.CodeInternal,
			fmt.Errorf("failed to sign DPoP proof: %w", err),
		)
	}
	if token != "" {
		// RFC 9449: MUST use the "DPoP" scheme for bound tokens.
		header.Set("Authorization", "DPoP "+token)
	}
	header.Set("DPoP", proof)
	return nil
}

func (c *Client) proof(method, urlPath, token string) (string, error) {
	ath := ""
	if token != "" {
		ath = dpop.ATH(token)
	}
	return c.proofer.Sign(method, c.base+urlPath, ath, c.currentNonce())
}

// Best effort, a failed prefetch keeps the cached nonce. Only a URL mismatch is returned, nothing works until fixed.
func (c *Client) refreshNonce(ctx context.Context) error {
	c.mu.Lock()
	fresh := within(c.learnedAt, nonceRefreshAfter) || within(c.triedAt, nonceRetryAfter)
	c.mu.Unlock()
	if fresh {
		return nil
	}

	nonce, err := FetchNonce(ctx, c.httpc, c.base)
	if errors.Is(err, ErrAPIURLMismatch) {
		return err
	}
	c.mu.Lock()
	c.triedAt = time.Now()
	c.mu.Unlock()
	if err != nil {
		slog.Debug("dpop nonce prefetch failed, using cached nonce", "error", err)
		return nil
	}
	c.Learn(nonce)
	return nil
}

func (c *Client) currentNonce() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nonce
}

// within measures on the wall clock, the monotonic one stops in a suspend and would keep an old nonce fresh.
func within(t time.Time, d time.Duration) bool {
	age := time.Since(t.Round(0))
	return age >= 0 && age <= d
}

// sameURL compares like the core compares an htu: host case, a default port and a trailing slash do not count.
func sameURL(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil {
		return false
	}
	return ua.Scheme == ub.Scheme &&
		strings.EqualFold(ua.Hostname(), ub.Hostname()) &&
		effectivePort(ua) == effectivePort(ub) &&
		path.Clean("/"+ua.EscapedPath()) == path.Clean("/"+ub.EscapedPath())
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch u.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// failedConn stands in for a stream that could not be signed. The real conn only sends on Send or a close.
type failedConn struct {
	connect.StreamingClientConn

	err error
}

func (c *failedConn) Send(any) error       { return c.err }
func (c *failedConn) Receive(any) error    { return c.err }
func (c *failedConn) CloseRequest() error  { return nil }
func (c *failedConn) CloseResponse() error { return nil }
