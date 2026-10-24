// Package dpopclient provides the DPoP-authenticated connect client stack
// shared by the Nokku binaries. It signs every RPC with a proof bound to the
// machine's signing key, carries the access token with the "DPoP" scheme,
// learns the server nonce, and retries once when the server rejects a stale
// nonce. Proofs bind to the configured API URL and nothing else.
package dpopclient

import (
	"cmp"
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

	"connectrpc.com/connect/v2"

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

// Intercept signs every call. A unary call is retried once when the server
// rejects the proof with a stale nonce that came with a fresh one. A stream is
// signed once and cannot retry, a stale-nonce rejection tears it down before
// the first message lands. A failed stream still records the nonce, so the
// next dial signs with it. A call that cannot be signed is never sent.
func (c *Client) Intercept(next connect.ClientFunc) connect.ClientFunc {
	return func(ctx context.Context, spec connect.Spec) (connect.ClientStream, error) {
		info, _ := connect.CallInfoForClientContext(ctx)
		if err := c.sign(ctx, info.RequestHeader(), spec.Procedure); err != nil {
			return nil, err
		}
		stream, err := next(ctx, spec)
		if err != nil {
			return nil, err
		}
		if spec.StreamType != connect.StreamTypeUnary {
			return &learningStream{ClientStream: stream, c: c, info: info}, nil
		}
		return &retryStream{ClientStream: stream, c: c, ctx: ctx, spec: spec, next: next, info: info}, nil
	}
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

// learnFrom records a fresh nonce from a stale-nonce rejection and reports
// whether the server advertised one. v2 errors carry no metadata, the nonce
// comes back as a response header or trailer.
func (c *Client) learnFrom(info *connect.CallInfo, err error) bool {
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		return false
	}
	nonce := cmp.Or(info.ResponseHeader().Get("DPoP-Nonce"), info.ResponseTrailer().Get("DPoP-Nonce"))
	c.Learn(nonce)
	return nonce != ""
}

// retryStream keeps the request of a unary call, so a stale-nonce rejection
// can be sent again with a fresh proof.
type retryStream struct {
	connect.ClientStream

	c       *Client
	ctx     context.Context
	spec    connect.Spec
	next    connect.ClientFunc
	info    *connect.CallInfo
	req     any
	retried bool
}

func (r *retryStream) Send(msg any) error {
	r.req = msg
	return r.ClientStream.Send(msg)
}

func (r *retryStream) Receive(msg any) error {
	err := r.ClientStream.Receive(msg)
	if err == nil || r.retried || r.req == nil || !r.c.learnFrom(r.info, err) {
		return err
	}
	r.retried = true
	_ = r.ClientStream.Close()

	// Wipe the rejected proof before signing again.
	r.info.RequestHeader().Delete("DPoP")
	if err = r.c.sign(r.ctx, r.info.RequestHeader(), r.spec.Procedure); err != nil {
		return err
	}
	stream, err := r.next(r.ctx, r.spec)
	if err != nil {
		return err
	}
	r.ClientStream = stream
	if err = stream.Send(r.req); err != nil {
		return err
	}
	if err = stream.CloseSend(); err != nil {
		return err
	}
	return stream.Receive(msg)
}

// learningStream records the nonce a rejected stream came back with.
type learningStream struct {
	connect.ClientStream

	c    *Client
	info *connect.CallInfo
}

func (l *learningStream) Receive(msg any) error {
	err := l.ClientStream.Receive(msg)
	if err != nil {
		l.c.learnFrom(l.info, err)
	}
	return err
}

// Without a token only procedures marked unbound are signed.
func (c *Client) sign(ctx context.Context, header *connect.Header, procedure string) error {
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
		return connect.Errorf(connect.CodeInternal, "failed to sign DPoP proof: %v", err).WithCause(err)
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
