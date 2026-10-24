package dpopclient

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokku/internal/dpop"
)

const (
	testBase      = "https://api.example.com"
	testProcedure = "/nokku.v1.DaemonService/SyncDaemon"
)

func testProofer(t *testing.T) *dpop.Proofer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p, err := dpop.NewProofer(key)
	require.NoError(t, err)
	return p
}

// testClient talks to testBase through rt. An empty token is a client that has no session yet.
func testClient(t *testing.T, rt http.RoundTripper, token string) *Client {
	t.Helper()
	return New(testProofer(t), &http.Client{Transport: rt}, func() string { return token }, Options{BaseURL: testBase})
}

// claims decodes the payload of a compact JWS.
func claims(t *testing.T, proof string) map[string]any {
	t.Helper()
	parts := strings.Split(proof, ".")
	require.Len(t, parts, 3, "proof is not a compact JWS: %q", proof)
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// An enrollment may go to another server than the one the stored token came from, so it never carries one.
func TestSignUnboundProcedure(t *testing.T) {
	const enroll = "/nokku.v1.DaemonService/EnrollDaemon"
	httpc := &http.Client{Transport: &countingTransport{}}
	c := New(testProofer(t), httpc, func() string { return "old-session" }, Options{
		BaseURL:           testBase,
		UnboundProcedures: map[string]bool{enroll: true},
		UserAgent:         "test-agent",
	})

	header := &connect.Header{}
	require.NoError(t, c.sign(t.Context(), header, enroll))
	assert.Empty(t, header.Get("Authorization"), "the stored token went to an unbound procedure")
	assert.Equal(t, "test-agent", header.Get("User-Agent"))
	got := claims(t, header.Get("DPoP"))
	assert.NotContains(t, got, "ath", "unbound proof must not carry ath")
	assert.Equal(t, testBase+enroll, got["htu"])
}

func TestSignWithoutTokenOrUnbound(t *testing.T) {
	c := testClient(t, &countingTransport{}, "")

	header := &connect.Header{}
	require.NoError(t, c.sign(t.Context(), header, testProcedure))
	assert.Empty(t, header.Get("DPoP"), "an unauthenticated procedure must not be signed")
	assert.Empty(t, header.Get("Authorization"), "an unauthenticated procedure must not carry a token")
}

func TestSignBoundToken(t *testing.T) {
	const token = "session-token"
	c := testClient(t, &countingTransport{}, token)

	header := &connect.Header{}
	require.NoError(t, c.sign(t.Context(), header, testProcedure))
	assert.Equal(t, "DPoP "+token, header.Get("Authorization"))
	got := claims(t, header.Get("DPoP"))
	assert.Equal(t, dpop.ATH(token), got["ath"])
	assert.Equal(t, http.MethodPost, got["htm"])
}

// countingTransport counts requests so a test can assert a prefetch did or did
// not happen.
type countingTransport struct {
	calls atomic.Int64
	nonce string
	base  string
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls.Add(1)
	h := http.Header{}
	if t.nonce != "" {
		h.Set("DPoP-Nonce", t.nonce)
	}
	if t.base != "" {
		h.Set(apiURLHeader, t.base)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     h,
		Body:       http.NoBody,
		Request:    req,
	}, nil
}

func TestRefreshNonceLearnsNonce(t *testing.T) {
	tr := &countingTransport{nonce: "fresh-nonce", base: testBase}
	c := testClient(t, tr, "")

	require.NoError(t, c.refreshNonce(t.Context()))
	assert.EqualValues(t, 1, tr.calls.Load())
	assert.Equal(t, "fresh-nonce", c.currentNonce())

	require.NoError(t, c.refreshNonce(t.Context()))
	assert.EqualValues(t, 1, tr.calls.Load(), "a learned nonce counts as fresh")
}

// TestLearnMarksNonceFresh is the regression for a learned nonce from a
// raw response not being treated as fresh, which caused a prefetch (and a
// potential rejection) on the next request.
func TestLearnMarksNonceFresh(t *testing.T) {
	tr := &countingTransport{}
	c := testClient(t, tr, "")

	c.Learn("learned")

	require.NoError(t, c.refreshNonce(t.Context()))
	assert.Zero(t, tr.calls.Load(), "a prefetch ran right after Learn")
	assert.Equal(t, "learned", c.currentNonce())
}

func TestLearnFrom(t *testing.T) {
	tr := &countingTransport{}
	c := testClient(t, tr, "")

	_, info := connect.NewClientContext(t.Context())
	info.ResponseHeader().Set("DPoP-Nonce", "from-error")

	assert.True(t, c.learnFrom(info, connect.NewError(connect.CodeUnauthenticated, "stale nonce")),
		"learnFrom must report a learned nonce")
	assert.Equal(t, "from-error", c.currentNonce())
	require.NoError(t, c.refreshNonce(t.Context()))
	assert.Zero(t, tr.calls.Load(), "a learned nonce is fresh")

	assert.False(t, c.learnFrom(info, connect.NewError(connect.CodeInternal, "boom")),
		"a non-authentication error carries no nonce to learn")
}

// fakeStream stands in for the transport. recv is what Receive answers.
type fakeStream struct {
	sent int
	recv func() error
}

func (s *fakeStream) SendHeaders() error { return nil }
func (s *fakeStream) Send(any) error     { s.sent++; return nil }
func (s *fakeStream) CloseSend() error   { return nil }
func (s *fakeStream) Close() error       { return nil }

func (s *fakeStream) Receive(any) error {
	if s.recv == nil {
		return nil
	}
	return s.recv()
}

// callUnary drives a stream the way connect.Client.CallUnary does.
func callUnary(ctx context.Context, open connect.ClientFunc) error {
	stream, err := open(ctx, connect.Spec{Procedure: testProcedure, StreamType: connect.StreamTypeUnary})
	if err != nil {
		return err
	}
	defer func() { _ = stream.Close() }()
	if err = stream.Send(&emptypb.Empty{}); err != nil {
		return err
	}
	if err = stream.CloseSend(); err != nil {
		return err
	}
	return stream.Receive(&emptypb.Empty{})
}

func TestUnaryRetriesAfterStaleNonce(t *testing.T) {
	c := testClient(t, &countingTransport{}, "tok")
	// Mark the nonce fresh so the retry path is reached without a prefetch.
	c.Learn("nonce-1")

	ctx, info := connect.NewClientContext(t.Context())
	var proofs []string
	var streams []*fakeStream
	next := func(context.Context, connect.Spec) (connect.ClientStream, error) {
		proofs = append(proofs, info.RequestHeader().Get("DPoP"))
		s := &fakeStream{}
		if len(proofs) == 1 {
			s.recv = func() error {
				info.ResponseHeader().Set("DPoP-Nonce", "nonce-2")
				return connect.NewError(connect.CodeUnauthenticated, "stale nonce")
			}
		}
		streams = append(streams, s)
		return s, nil
	}

	require.NoError(t, callUnary(ctx, c.Intercept(next)))
	require.Len(t, proofs, 2, "one retry")
	assert.NotEqual(t, proofs[0], proofs[1], "the retry must carry a freshly signed proof")
	assert.Equal(t, "nonce-2", claims(t, proofs[1])["nonce"])
	assert.Equal(t, 1, streams[1].sent, "the retry must send the request again")
}

func TestUnaryRetriesOnlyOnce(t *testing.T) {
	c := testClient(t, &countingTransport{}, "tok")
	c.Learn("nonce-1")

	ctx, info := connect.NewClientContext(t.Context())
	opened := 0
	next := func(context.Context, connect.Spec) (connect.ClientStream, error) {
		opened++
		return &fakeStream{recv: func() error {
			info.ResponseHeader().Set("DPoP-Nonce", "nonce-again")
			return connect.NewError(connect.CodeUnauthenticated, "stale nonce")
		}}, nil
	}

	err := callUnary(ctx, c.Intercept(next))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	assert.Equal(t, 2, opened, "a second stale nonce must not loop")
}

func TestNewHTTPClient(t *testing.T) {
	c, err := NewHTTPClient(nil, 3*time.Second)
	require.NoError(t, err)
	tr, ok := c.Transport.(*http.Transport)
	require.True(t, ok, "transport is %T, want *http.Transport", c.Transport)
	require.NotNil(t, tr.Protocols)
	assert.False(t, tr.Protocols.HTTP1(), "client must be HTTP/2 only")
	require.NotNil(t, tr.TLSClientConfig)
	assert.EqualValues(t, tls.VersionTLS13, tr.TLSClientConfig.MinVersion, "client must require TLS 1.3")
	assert.False(t, tr.TLSClientConfig.InsecureSkipVerify, "client must verify the server")
}

func TestProofBindsToTheConfiguredURL(t *testing.T) {
	tr := &countingTransport{nonce: "n"}
	c := New(testProofer(t), &http.Client{Transport: tr}, func() string { return "" }, Options{BaseURL: testBase + "/"})

	proof, err := c.Proof(t.Context(), http.MethodPost, "/auth/device/token")
	require.NoError(t, err)
	got := claims(t, proof)
	assert.Equal(t, testBase+"/auth/device/token", got["htu"])
	assert.Equal(t, "n", got["nonce"], "a proof asked for by hand skipped the nonce fetch")
}

func TestSameURL(t *testing.T) {
	for name, tc := range map[string]struct {
		advertised string
		same       bool
	}{
		"equal":          {"https://api.example.com", true},
		"host case":      {"https://API.example.com", true},
		"default port":   {"https://api.example.com:443", true},
		"trailing slash": {"https://api.example.com/", true},
		"other host":     {"https://other.example.com", false},
		"other port":     {"https://api.example.com:8443", false},
		"other scheme":   {"http://api.example.com", false},
		"path prefix":    {"https://api.example.com/nokku", false},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.same, sameURL(tc.advertised, testBase))
		})
	}
}

func TestFetchNonceRefusesAServerAtAnotherURL(t *testing.T) {
	tr := &countingTransport{nonce: "n", base: "https://other.example.com"}

	_, err := FetchNonce(t.Context(), &http.Client{Transport: tr}, testBase)
	require.ErrorIs(t, err, ErrAPIURLMismatch)
	assert.ErrorContains(t, err, "https://other.example.com", "the error names the URL to use")
}

// The mismatch is checked again on every call, so the reason never turns into a bare rejection by the server.
func TestUnaryStopsOnAURLMismatch(t *testing.T) {
	tr := &countingTransport{nonce: "n", base: "https://other.example.com"}
	c := testClient(t, tr, "tok")
	sent := 0
	call := c.Intercept(func(context.Context, connect.Spec) (connect.ClientStream, error) {
		sent++
		return &fakeStream{}, nil
	})

	for range 2 {
		ctx, _ := connect.NewClientContext(t.Context())
		err := callUnary(ctx, call)
		require.ErrorIs(t, err, ErrAPIURLMismatch)
		assert.NotEqual(t, connect.CodeUnauthenticated, connect.CodeOf(err), "it must not read as a rejected session")
	}
	assert.Zero(t, sent, "a request went to a server at another URL")
	assert.EqualValues(t, 2, tr.calls.Load())
}

func h2cServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func TestHTTPClientDoesNotFollowRedirects(t *testing.T) {
	var followed atomic.Bool
	target := h2cServer(t, func(w http.ResponseWriter, _ *http.Request) {
		followed.Store(true)
		w.Header().Set("DPoP-Nonce", "from-another-host")
	})
	srv := h2cServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	})
	httpc, err := NewHTTPClient(nil, time.Second)
	require.NoError(t, err)

	nonce, err := FetchNonce(t.Context(), httpc, srv.URL)
	require.NoError(t, err)
	assert.Empty(t, nonce, "a nonce was learned from a redirect target")
	assert.False(t, followed.Load())
}

// hangingTransport accepts the request and never answers.
type hangingTransport struct{ calls atomic.Int64 }

func (t *hangingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls.Add(1)
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func TestPrefetchIsBoundedAndNotRepeatedAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tr := &hangingTransport{}
		c := testClient(t, tr, "")

		start := time.Now()
		require.NoError(t, c.refreshNonce(t.Context()), "a failed prefetch is best effort")
		assert.Equal(t, nonceFetchTimeout, time.Since(start), "the prefetch has no bound of its own")

		require.NoError(t, c.refreshNonce(t.Context()))
		assert.EqualValues(t, 1, tr.calls.Load(), "a failed prefetch was repeated at once")

		time.Sleep(nonceRetryAfter + time.Second)
		require.NoError(t, c.refreshNonce(t.Context()))
		assert.EqualValues(t, 2, tr.calls.Load(), "the prefetch is tried again after a while")
	})
}

func TestPrefetchWithoutANonceIsNotRepeatedAtOnce(t *testing.T) {
	tr := &countingTransport{}
	c := testClient(t, tr, "")

	for range 3 {
		require.NoError(t, c.refreshNonce(t.Context()))
	}
	assert.EqualValues(t, 1, tr.calls.Load())
}

// The server only promises a nonce 5 minutes, so the refresh has to come before that.
func TestNonceIsRefreshedBeforeTheServerDropsIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tr := &countingTransport{nonce: "n2"}
		c := testClient(t, tr, "")
		c.Learn("n1")

		time.Sleep(3 * time.Minute)
		require.NoError(t, c.refreshNonce(t.Context()))
		assert.Zero(t, tr.calls.Load(), "a young nonce was fetched again")

		time.Sleep(90 * time.Second)
		require.NoError(t, c.refreshNonce(t.Context()))
		assert.EqualValues(t, 1, tr.calls.Load())
		assert.Equal(t, "n2", c.currentNonce())
	})
}

func TestNonceAgeUsesTheWallClock(t *testing.T) {
	assert.True(t, within(time.Now().Add(-time.Minute), 2*time.Minute))
	assert.False(t, within(time.Now().Add(-3*time.Minute), 2*time.Minute))
	assert.False(t, within(time.Now().Add(time.Hour), 2*time.Minute), "a clock set back must not keep a nonce")
	assert.False(t, within(time.Time{}, 2*time.Minute))
}

// brokenSigner has a public key and cannot sign, like a TPM that went away.
type brokenSigner struct{ pub crypto.PublicKey }

func (s brokenSigner) Public() crypto.PublicKey { return s.pub }

func (brokenSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("tpm is gone")
}

func TestStreamThatCannotBeSignedIsNeverSent(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	proofer, err := dpop.NewProofer(brokenSigner{pub: &key.PublicKey})
	require.NoError(t, err)
	c := New(proofer, &http.Client{Transport: &countingTransport{nonce: "n"}}, func() string { return "tok" },
		Options{BaseURL: testBase})

	ctx, info := connect.NewClientContext(t.Context())
	opened := false
	open := c.Intercept(func(context.Context, connect.Spec) (connect.ClientStream, error) {
		opened = true
		return &fakeStream{}, nil
	})
	_, err = open(ctx, connect.Spec{Procedure: testProcedure, StreamType: connect.StreamTypeBidi})

	require.ErrorContains(t, err, "tpm is gone")
	assert.False(t, opened, "the stream went out without a proof")
	assert.Empty(t, info.RequestHeader().Get("Authorization"), "the token was set although there is no proof")
}

func TestStreamIsSigned(t *testing.T) {
	c := testClient(t, &countingTransport{nonce: "n"}, "tok")

	ctx, info := connect.NewClientContext(t.Context())
	inner := &fakeStream{}
	open := c.Intercept(func(context.Context, connect.Spec) (connect.ClientStream, error) { return inner, nil })
	stream, err := open(ctx, connect.Spec{Procedure: testProcedure, StreamType: connect.StreamTypeBidi})
	require.NoError(t, err)

	require.NoError(t, stream.Send(&emptypb.Empty{}))
	assert.Equal(t, 1, inner.sent)
	assert.Equal(t, "DPoP tok", info.RequestHeader().Get("Authorization"))
	assert.Equal(t, "n", claims(t, info.RequestHeader().Get("DPoP"))["nonce"])
}

// A daemon redials its control stream, the nonce of the rejected one must sign the next.
func TestRejectedStreamLearnsTheNonce(t *testing.T) {
	c := testClient(t, &countingTransport{nonce: "n"}, "tok")

	ctx, info := connect.NewClientContext(t.Context())
	open := c.Intercept(func(context.Context, connect.Spec) (connect.ClientStream, error) {
		return &fakeStream{recv: func() error {
			info.ResponseHeader().Set("DPoP-Nonce", "fresh")
			return connect.NewError(connect.CodeUnauthenticated, "stale nonce")
		}}, nil
	})
	stream, err := open(ctx, connect.Spec{Procedure: testProcedure, StreamType: connect.StreamTypeBidi})
	require.NoError(t, err)

	require.Error(t, stream.Receive(&emptypb.Empty{}))
	assert.Equal(t, "fresh", c.currentNonce())
}

// nonceCore turns the first call down with a fresh nonce, the way core answers a stale proof.
type nonceCore struct {
	nokkuv1connect.UnimplementedDaemonControlServiceHandler

	calls  atomic.Int32
	proofs []string
}

func (n *nonceCore) reject(next connect.ServerFunc) connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
		info, _ := connect.CallInfoForServerContext(ctx)
		n.proofs = append(n.proofs, info.RequestHeader().Get("DPoP"))
		if n.calls.Add(1) == 1 {
			info.ResponseHeader().Set("DPoP-Nonce", "n2")
			return connect.NewError(connect.CodeUnauthenticated, "stale DPoP nonce")
		}
		return next(ctx, spec, stream)
	}
}

func (*nonceCore) SyncDaemon(context.Context, *nokkuv1.SyncDaemonRequest) (*nokkuv1.SyncDaemonResponse, error) {
	return &nokkuv1.SyncDaemonResponse{}, nil
}

// nonceServer serves core behind the real HTTP transport, so the nonce travels as a response header.
func nonceServer(t *testing.T, core *nonceCore) (*Client, nokkuv1connect.DaemonControlServiceClient) {
	t.Helper()
	server := connect.NewServer(core.reject)
	nokkuv1connect.RegisterDaemonControlServiceHandler(server, core)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	srv := h2cServer(t, mux.ServeHTTP)

	httpc, err := NewHTTPClient(nil, time.Second)
	require.NoError(t, err)
	c := New(testProofer(t), httpc, func() string { return "tok" }, Options{BaseURL: srv.URL})
	// Fresh, so no prefetch runs against a server without the nonce route.
	c.Learn("n1")
	return c, nokkuv1connect.NewDaemonControlServiceClient(
		connect.NewClient(connecthttp.NewTransport(httpc, srv.URL), c.Intercept),
	)
}

func TestUnaryRetryOverHTTP(t *testing.T) {
	core := &nonceCore{}
	_, client := nonceServer(t, core)

	_, err := client.SyncDaemon(t.Context(), &nokkuv1.SyncDaemonRequest{})
	require.NoError(t, err, "the retry with the fresh nonce must go through")
	require.EqualValues(t, 2, core.calls.Load(), "one retry")
	assert.Equal(t, "n1", claims(t, core.proofs[0])["nonce"])
	assert.Equal(t, "n2", claims(t, core.proofs[1])["nonce"])
}

func TestRejectedStreamLearnsTheNonceOverHTTP(t *testing.T) {
	core := &nonceCore{}
	c, client := nonceServer(t, core)

	stream, err := client.Connect(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { _ = stream.Close() })
	require.NoError(t, stream.Send(&nokkuv1.ConnectRequest{}))

	_, err = stream.Receive()
	require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	assert.Equal(t, "n2", c.currentNonce(), "the next dial must sign with the nonce the rejection carried")
}
