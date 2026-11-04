// Package dpopclient is the DPoP-authenticated connect client the Nokku
// binaries share. Proofs bind to the configured API URL and nothing else.
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

// ErrAPIURLMismatch stops calls, proofs only verify for the server's own URL.
var ErrAPIURLMismatch = errors.New("dpopclient: the server is not at the configured API URL")

type Options struct {
	// BaseURL must be the URL the server knows itself by, proofs bind to it.
	BaseURL string
	// UnboundProcedures get a proof with no ath, and never a stored token.
	UnboundProcedures map[string]bool
	UserAgent         string
}

// Client is safe for concurrent use.
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

// retryStream keeps a unary request to resend it after a stale-nonce rejection.
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

// learningStream records the nonce a rejected stream came back with.
type learningStream struct {
	connect.ClientStream

	c    *Client
	info *connect.CallInfo
}

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

// NewHTTPClient follows no redirect, a proof only holds for the URL it signs.
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
	// TCP keepalive stays quiet with data in flight, the ping ends a dead stream in 90s.
	t.HTTP2 = &http.HTTP2Config{SendPingTimeout: 60 * time.Second, PingTimeout: 30 * time.Second}
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

// FetchNonce saves the first protected request a 401 round trip.
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

	if advertised := resp.Header.Get(apiURLHeader); advertised != "" && !dpop.SameURL(advertised, baseURL) {
		return "", fmt.Errorf("%w: %s says it is at %q, use that URL", ErrAPIURLMismatch, baseURL, advertised)
	}
	return resp.Header.Get("DPoP-Nonce"), nil
}

// Intercept retries a unary call once on a stale nonce. A stream cannot retry,
// it dies before the first message and records the nonce for the next dial. A
// call that cannot be signed is never sent.
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

// Proof signs raw HTTP calls like the device flow, refreshing an old nonce.
func (c *Client) Proof(ctx context.Context, method, urlPath string) (string, error) {
	if err := c.refreshNonce(ctx); err != nil {
		return "", err
	}
	return c.proof(method, urlPath, c.token())
}

// Learn records a nonce from a raw response, the next proof skips the prefetch.
func (c *Client) Learn(nonce string) {
	if nonce == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nonce = nonce
	c.learnedAt = time.Now()
}

// v2 errors carry no metadata, the nonce comes as a response header or trailer.
func (c *Client) learnFrom(info *connect.CallInfo, err error) bool {
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		return false
	}
	nonce := cmp.Or(info.ResponseHeader().Get("DPoP-Nonce"), info.ResponseTrailer().Get("DPoP-Nonce"))
	c.Learn(nonce)
	return nonce != ""
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
		// An unbound call may go to another server than the token came from.
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

// Best effort, only a URL mismatch is returned, nothing works until it's fixed.
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

// Wall clock, a suspend stops the monotonic one, an old nonce would look fresh.
func within(t time.Time, d time.Duration) bool {
	age := time.Since(t.Round(0))
	return age >= 0 && age <= d
}
