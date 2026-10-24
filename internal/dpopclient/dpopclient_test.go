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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"

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

	header := http.Header{}
	require.NoError(t, c.sign(t.Context(), header, enroll))
	assert.Empty(t, header.Get("Authorization"), "the stored token went to an unbound procedure")
	assert.Equal(t, "test-agent", header.Get("User-Agent"))
	got := claims(t, header.Get("DPoP"))
	assert.NotContains(t, got, "ath", "unbound proof must not carry ath")
	assert.Equal(t, testBase+enroll, got["htu"])
}

func TestSignWithoutTokenOrUnbound(t *testing.T) {
	c := testClient(t, &countingTransport{}, "")

	header := http.Header{}
	require.NoError(t, c.sign(t.Context(), header, testProcedure))
	assert.Empty(t, header.Get("DPoP"), "an unauthenticated procedure must not be signed")
	assert.Empty(t, header.Get("Authorization"), "an unauthenticated procedure must not carry a token")
}

func TestSignBoundToken(t *testing.T) {
	const token = "session-token"
	c := testClient(t, &countingTransport{}, token)

	header := http.Header{}
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

func TestLearnFromError(t *testing.T) {
	tr := &countingTransport{}
	c := testClient(t, tr, "")

	err := connect.NewError(connect.CodeUnauthenticated, errors.New("stale nonce"))
	err.Meta().Set("DPoP-Nonce", "from-error")

	assert.True(t, c.LearnFromError(err), "LearnFromError must report a learned nonce")
	assert.Equal(t, "from-error", c.currentNonce())
	require.NoError(t, c.refreshNonce(t.Context()))
	assert.Zero(t, tr.calls.Load(), "a learned nonce is fresh")

	assert.False(t, c.LearnFromError(connect.NewError(connect.CodeInternal, errors.New("boom"))),
		"a non-authentication error carries no nonce to learn")
}

func TestWrapUnaryRetriesAfterStaleNonce(t *testing.T) {
	c := testClient(t, &countingTransport{}, "tok")
	// Mark the nonce fresh so the retry path is reached without a prefetch.
	c.Learn("nonce-1")

	var proofs []string
	next := func(_ context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		proofs = append(proofs, req.Header().Get("DPoP"))
		if len(proofs) == 1 {
			err := connect.NewError(connect.CodeUnauthenticated, errors.New("stale nonce"))
			err.Meta().Set("DPoP-Nonce", "nonce-2")
			return nil, err
		}
		return connect.NewResponse(&emptypb.Empty{}), nil
	}

	resp, err := c.WrapUnary(next)(t.Context(), connect.NewRequest(&emptypb.Empty{}))
	require.NoError(t, err)
	assert.NotNil(t, resp)
	require.Len(t, proofs, 2, "one retry")
	assert.NotEqual(t, proofs[0], proofs[1], "the retry must carry a freshly signed proof")
	assert.Equal(t, "nonce-2", claims(t, proofs[1])["nonce"])
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
func TestWrapUnaryStopsOnAURLMismatch(t *testing.T) {
	tr := &countingTransport{nonce: "n", base: "https://other.example.com"}
	c := testClient(t, tr, "tok")
	sent := 0
	call := c.WrapUnary(func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
		sent++
		return connect.NewResponse(&emptypb.Empty{}), nil
	})

	for range 2 {
		_, err := call(t.Context(), connect.NewRequest(&emptypb.Empty{}))
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

// recordingConn is a stream conn that counts what would reach the network.
type recordingConn struct {
	connect.StreamingClientConn

	header http.Header
	sent   int
}

func (c *recordingConn) RequestHeader() http.Header { return c.header }
func (c *recordingConn) Send(any) error             { c.sent++; return nil }
func (c *recordingConn) Receive(any) error          { c.sent++; return nil }
func (c *recordingConn) CloseRequest() error        { c.sent++; return nil }
func (c *recordingConn) CloseResponse() error       { c.sent++; return nil }

func TestStreamThatCannotBeSignedIsNeverSent(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	proofer, err := dpop.NewProofer(brokenSigner{pub: &key.PublicKey})
	require.NoError(t, err)
	c := New(proofer, &http.Client{Transport: &countingTransport{nonce: "n"}}, func() string { return "tok" },
		Options{BaseURL: testBase})

	inner := &recordingConn{header: http.Header{}}
	open := c.WrapStreamingClient(func(context.Context, connect.Spec) connect.StreamingClientConn { return inner })
	conn := open(t.Context(), connect.Spec{Procedure: testProcedure})

	require.ErrorContains(t, conn.Send(&emptypb.Empty{}), "tpm is gone")
	require.ErrorContains(t, conn.Receive(&emptypb.Empty{}), "tpm is gone")
	require.NoError(t, conn.CloseRequest())
	require.NoError(t, conn.CloseResponse())
	assert.Zero(t, inner.sent, "the stream went out without a proof")
	assert.Empty(t, inner.header.Get("Authorization"), "the token was set although there is no proof")
}

func TestStreamIsSigned(t *testing.T) {
	c := testClient(t, &countingTransport{nonce: "n"}, "tok")

	inner := &recordingConn{header: http.Header{}}
	open := c.WrapStreamingClient(func(context.Context, connect.Spec) connect.StreamingClientConn { return inner })
	conn := open(t.Context(), connect.Spec{Procedure: testProcedure})

	require.NoError(t, conn.Send(&emptypb.Empty{}))
	assert.Equal(t, 1, inner.sent)
	assert.Equal(t, "DPoP tok", inner.header.Get("Authorization"))
	assert.Equal(t, "n", claims(t, inner.header.Get("DPoP"))["nonce"])
}
