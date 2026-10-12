package dpopclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/nokku-sh/nokku/internal/dpop"
)

func testProofer(t *testing.T) *dpop.Proofer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p, err := dpop.NewProofer(key, dpop.ProoferOptions{})
	if err != nil {
		t.Fatalf("NewProofer: %v", err)
	}
	return p
}

// claims decodes the payload of a compact JWS.
func claims(t *testing.T, proof string) map[string]any {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("proof is not a compact JWS: %q", proof)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var out map[string]any
	if err = json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return out
}

func TestSignUnboundProcedure(t *testing.T) {
	httpc := &http.Client{}
	c := New(testProofer(t), httpc, func() string { return "" }, Options{
		BaseURL:           "https://api.example.com",
		UnboundProcedures: map[string]bool{"/nokku.v1.DaemonService/EnrollDaemon": true},
		UserAgent:         "test-agent",
	})

	header := http.Header{}
	if err := c.sign(header, "/nokku.v1.DaemonService/EnrollDaemon"); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got := header.Get("Authorization"); got != "" {
		t.Fatalf("unbound proof must not carry Authorization, got %q", got)
	}
	if got := header.Get("User-Agent"); got != "test-agent" {
		t.Fatalf("User-Agent = %q, want test-agent", got)
	}
	got := claims(t, header.Get("DPoP"))
	if _, ok := got["ath"]; ok {
		t.Fatal("unbound proof must not carry ath")
	}
	if got["htu"] != "https://api.example.com/nokku.v1.DaemonService/EnrollDaemon" {
		t.Fatalf("htu = %v", got["htu"])
	}
}

func TestSignWithoutTokenOrUnbound(t *testing.T) {
	c := New(testProofer(t), &http.Client{}, func() string { return "" }, Options{
		BaseURL: "https://api.example.com",
	})
	header := http.Header{}
	if err := c.sign(header, "/nokku.v1.DaemonService/SyncDaemon"); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if header.Get("DPoP") != "" {
		t.Fatal("an unauthenticated procedure must not be signed")
	}
	if header.Get("Authorization") != "" {
		t.Fatal("an unauthenticated procedure must not carry a token")
	}
}

func TestSignBoundToken(t *testing.T) {
	const token = "session-token"
	c := New(testProofer(t), &http.Client{}, func() string { return token }, Options{
		BaseURL: "https://api.example.com",
	})
	header := http.Header{}
	if err := c.sign(header, "/nokku.v1.DaemonService/SyncDaemon"); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got := header.Get("Authorization"); got != "DPoP "+token {
		t.Fatalf("Authorization = %q, want DPoP %s", got, token)
	}
	got := claims(t, header.Get("DPoP"))
	if got["ath"] != dpop.ATH(token) {
		t.Fatalf("ath = %v, want %s", got["ath"], dpop.ATH(token))
	}
	if got["htm"] != http.MethodPost {
		t.Fatalf("htm = %v, want POST", got["htm"])
	}
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
		h.Set(APIURLHeader, t.base)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     h,
		Body:       http.NoBody,
		Request:    req,
	}, nil
}

func TestRefreshNonceLearnsHeaders(t *testing.T) {
	tr := &countingTransport{nonce: "fresh-nonce", base: "https://canonical.example.com"}
	c := New(testProofer(t), &http.Client{Transport: tr}, func() string { return "" }, Options{
		BaseURL: "https://configured.example.com",
	})

	c.refreshNonce(context.Background())
	if got := tr.calls.Load(); got != 1 {
		t.Fatalf("prefetch calls = %d, want 1", got)
	}
	if got := c.currentNonce(); got != "fresh-nonce" {
		t.Fatalf("nonce = %q, want fresh-nonce", got)
	}
	if got := c.HtuBase(); got != "https://canonical.example.com" {
		t.Fatalf("HtuBase = %q, want the advertised canonical URL", got)
	}

	// A learned nonce counts as fresh: no second prefetch.
	c.refreshNonce(context.Background())
	if got := tr.calls.Load(); got != 1 {
		t.Fatalf("prefetch calls = %d, want 1 (nonce is fresh)", got)
	}
}

// TestLearnHeadersMarksNonceFresh is the regression for a learned nonce from a
// raw response not being treated as fresh, which caused a prefetch (and a
// potential rejection) on the next request.
func TestLearnHeadersMarksNonceFresh(t *testing.T) {
	tr := &countingTransport{}
	c := New(testProofer(t), &http.Client{Transport: tr}, func() string { return "" }, Options{
		BaseURL: "https://configured.example.com",
	})

	h := http.Header{}
	h.Set("DPoP-Nonce", "learned")
	h.Set(APIURLHeader, "https://canonical.example.com")
	c.LearnHeaders(h)

	c.refreshNonce(context.Background())
	if got := tr.calls.Load(); got != 0 {
		t.Fatalf("prefetch calls after LearnHeaders = %d, want 0", got)
	}
	if got := c.currentNonce(); got != "learned" {
		t.Fatalf("nonce = %q, want learned", got)
	}
}

func TestLearnFromError(t *testing.T) {
	tr := &countingTransport{}
	c := New(testProofer(t), &http.Client{Transport: tr}, func() string { return "" }, Options{
		BaseURL: "https://configured.example.com",
	})

	err := connect.NewError(connect.CodeUnauthenticated, errors.New("stale nonce"))
	err.Meta().Set("DPoP-Nonce", "from-error")
	err.Meta().Set(APIURLHeader, "https://canonical.example.com")

	if !c.LearnFromError(err) {
		t.Fatal("LearnFromError must report a learned nonce")
	}
	if got := c.currentNonce(); got != "from-error" {
		t.Fatalf("nonce = %q, want from-error", got)
	}
	if got := c.HtuBase(); got != "https://canonical.example.com" {
		t.Fatalf("HtuBase = %q, want the canonical URL", got)
	}
	c.refreshNonce(context.Background())
	if got := tr.calls.Load(); got != 0 {
		t.Fatalf("prefetch calls = %d, want 0 (a learned nonce is fresh)", got)
	}

	// A non-unauthenticated error carries no nonce to learn.
	if c.LearnFromError(connect.NewError(connect.CodeInternal, errors.New("boom"))) {
		t.Fatal("LearnFromError must ignore non-authentication errors")
	}
}

func TestWrapUnaryRetriesAfterStaleNonce(t *testing.T) {
	tr := &countingTransport{}
	c := New(testProofer(t), &http.Client{Transport: tr}, func() string { return "tok" }, Options{
		BaseURL: "https://api.example.com",
	})
	// Mark the nonce fresh so the retry path is reached without a prefetch.
	c.Learn("nonce-1", "")

	calls := 0
	var proofs []string
	next := func(_ context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		calls++
		proofs = append(proofs, req.Header().Get("DPoP"))
		if calls == 1 {
			err := connect.NewError(connect.CodeUnauthenticated, errors.New("stale nonce"))
			err.Meta().Set("DPoP-Nonce", "nonce-2")
			return nil, err
		}
		return connect.NewResponse(&emptypb.Empty{}), nil
	}

	resp, err := c.WrapUnary(next)(context.Background(), connect.NewRequest(&emptypb.Empty{}))
	if err != nil {
		t.Fatalf("WrapUnary: %v", err)
	}
	if resp == nil {
		t.Fatal("WrapUnary returned no response")
	}
	if calls != 2 {
		t.Fatalf("next calls = %d, want 2 (one retry)", calls)
	}
	if proofs[0] == proofs[1] {
		t.Fatal("the retry must carry a freshly signed proof")
	}
	if got := claims(t, proofs[1])["nonce"]; got != "nonce-2" {
		t.Fatalf("retry nonce = %v, want nonce-2", got)
	}
}

func TestNewHTTPClient(t *testing.T) {
	c, err := NewHTTPClient(nil, 3*time.Second)
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", c.Transport)
	}
	if tr.Protocols == nil || tr.Protocols.HTTP1() {
		t.Fatal("client must be HTTP/2 only")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("client must require TLS 1.3")
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("client must verify the server")
	}
}
