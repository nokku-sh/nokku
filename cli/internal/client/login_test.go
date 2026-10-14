package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/dpop"
	"github.com/nokku-sh/nokku/internal/dpopclient"

	"github.com/nokku-sh/nokku/cli/internal/state"
)

// fakeDeviceFlow mirrors iam.DeviceFlow closely enough for the poll loop, DPoP checks and replay store included.
type fakeDeviceFlow struct {
	mu         sync.Mutex
	grants     map[string]*fakeGrant // by device code
	replay     map[string]bool
	nonce      string
	baseURL    string
	violations map[string]int
	lastPoll   map[string]time.Time
}

type fakeGrant struct {
	deviceCode string
	userCode   string
	status     string
	userAgent  string
}

func newFakeDeviceFlow(t *testing.T) (*fakeDeviceFlow, *httptest.Server) {
	t.Helper()
	f := &fakeDeviceFlow{
		grants:     map[string]*fakeGrant{},
		replay:     map[string]bool{},
		nonce:      "test-nonce",
		lastPoll:   map[string]time.Time{},
		violations: map[string]int{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/device", f.begin)
	mux.HandleFunc("POST /auth/device/token", f.poll)
	mux.HandleFunc("GET /auth/device/nonce", f.nonceEndpoint)
	srv := httptest.NewServer(mux)
	f.baseURL = srv.URL
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeDeviceFlow) begin(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	g := &fakeGrant{
		deviceCode: fmt.Sprintf("dev-%d", len(f.grants)),
		userCode:   fmt.Sprintf("USER-%d", len(f.grants)),
		status:     "pending",
		userAgent:  r.Header.Get("User-Agent"),
	}
	f.grants[g.deviceCode] = g
	writeJSON(w, map[string]any{
		"device_code":               g.deviceCode,
		"user_code":                 g.userCode,
		"verification_uri":          f.baseURL + "/device",
		"verification_uri_complete": f.baseURL + "/device?user_code=" + g.userCode,
		"interval":                  1,
	})
}

func (f *fakeDeviceFlow) poll(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	code := r.FormValue("device_code")
	g, ok := f.grants[code]
	if !ok {
		writeOAuthErr(w, "expired_token")
		return
	}
	switch g.status {
	case "pending":
		// pollTrack: the required interval grows by 5s per too-fast poll.
		required := time.Second + time.Duration(f.violations[code])*5*time.Second
		now := time.Now()
		if last := f.lastPoll[code]; !last.IsZero() && now.Sub(last) < required {
			f.violations[code]++
			writeOAuthErr(w, "slow_down")
			return
		}
		f.lastPoll[code] = now
		writeOAuthErr(w, "authorization_pending")
	case "denied":
		delete(f.grants, code)
		writeOAuthErr(w, "access_denied")
	case "approved":
		jkt, derr := f.verifyProof(r)
		if derr != "" {
			// Like the server, the canonical URL and the nonce ride every proof failure.
			w.Header().Set("Nokku-Api-Url", f.baseURL)
			w.Header().Set("DPoP-Nonce", f.nonce)
			writeOAuthErr(w, derr)
			return
		}
		delete(f.grants, code)
		writeJSON(w, map[string]any{
			"access_token": "tok-for-" + jkt,
			"token_type":   "DPoP",
		})
	}
}

func (f *fakeDeviceFlow) nonceEndpoint(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Nokku-Api-Url", f.baseURL)
	w.Header().Set("DPoP-Nonce", f.nonce)
	w.WriteHeader(http.StatusNoContent)
}

// verifyProof checks the claims the server checks at issuance, not the signature.
func (f *fakeDeviceFlow) verifyProof(r *http.Request) (string, string) {
	proof := r.Header.Get("DPoP")
	if proof == "" {
		return "", "" // unbound session, still succeeds
	}
	payload, err := base64.RawURLEncoding.DecodeString(
		strings.Split(proof, ".")[1],
	)
	if err != nil {
		return "", "invalid_dpop_proof"
	}
	var claims struct {
		HTM   string `json:"htm"`
		HTU   string `json:"htu"`
		IAT   int64  `json:"iat"`
		JTI   string `json:"jti"`
		Nonce string `json:"nonce"`
	}
	if err = json.Unmarshal(payload, &claims); err != nil {
		return "", "invalid_dpop_proof"
	}
	if claims.HTM != http.MethodPost ||
		!strings.EqualFold(claims.HTU, f.baseURL+"/auth/device/token") {
		return "", "invalid_dpop_proof"
	}
	if claims.IAT == 0 || time.Since(time.Unix(claims.IAT, 0)) > time.Minute {
		return "", "invalid_dpop_proof"
	}
	if claims.Nonce != f.nonce {
		return "", "use_dpop_nonce"
	}
	if f.replay[claims.JTI] {
		return "", "invalid_dpop_proof"
	}
	f.replay[claims.JTI] = true
	return "jkt", ""
}

func (f *fakeDeviceFlow) approve(deviceCode string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grants[deviceCode].status = "approved"
}

func writeOAuthErr(w http.ResponseWriter, code string) {
	writeJSON(w, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func newTestProofer(t *testing.T) *dpop.Proofer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p, err := dpop.NewProofer(key)
	require.NoError(t, err)
	return p
}

// runDeviceLogin drives deviceLogin's path and approves shortly after, like a user clicking accept.
func runDeviceLogin(t *testing.T, c *Client, f *fakeDeviceFlow) (string, error) {
	t.Helper()
	d, err := c.beginDeviceAuth(context.Background())
	require.NoError(t, err)

	go func() {
		time.Sleep(1500 * time.Millisecond)
		f.approve(d.DeviceCode)
	}()

	token, _, err := c.pollDeviceToken(context.Background(), d.DeviceCode, d.Interval)
	return token, err
}

func TestDeviceFlowTwoConsecutiveLogins(t *testing.T) {
	f, srv := newFakeDeviceFlow(t)

	c := &Client{State: &state.State{APIURL: srv.URL}, httpc: srv.Client()}
	c.dpop = dpopclient.New(
		newTestProofer(t),
		srv.Client(),
		func() string { return c.State.SessionToken },
		dpopclient.Options{BaseURL: c.State.APIURL},
	)

	for i := range 2 {
		token, err := runDeviceLogin(t, c, f)
		require.NoError(t, err, "login %d", i+1)
		assert.NotEmpty(t, token, "login %d: empty token", i+1)
	}

	// The approval page shows who asked, so the request has to say it is nk.
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, g := range f.grants {
		assert.True(t, strings.HasPrefix(g.userAgent, "nk/"), "device request user agent = %q", g.userAgent)
	}
}

// The OS opener also launches files and custom schemes, so a core may only send a web page.
func TestDeviceFlowRejectsNonWebLink(t *testing.T) {
	f, srv := newFakeDeviceFlow(t)
	f.baseURL = "file:///etc/passwd"
	c := &Client{State: &state.State{APIURL: srv.URL}, httpc: srv.Client()}
	c.dpop = dpopclient.New(
		newTestProofer(t),
		srv.Client(),
		func() string { return c.State.SessionToken },
		dpopclient.Options{BaseURL: c.State.APIURL},
	)

	_, err := c.beginDeviceAuth(t.Context())
	require.Error(t, err, "a file link was accepted")
}

// Waiting cannot fix any of these answers, so the poll loop ends on them.
func TestPollDeviceTokenStopsOnFinalAnswers(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		status int
		body   string
		want   string
	}{
		"denied":             {http.StatusBadRequest, `{"error":"access_denied"}`, "sign-in was denied in the browser"},
		"expired":            {http.StatusBadRequest, `{"error":"expired_token"}`, "sign-in code expired, run nk login again"},
		"unknown code":       {http.StatusBadRequest, `{"error":"server_error"}`, "device authorization failed: server_error"},
		"oauth error on 200": {http.StatusOK, `{"error":"access_denied"}`, "sign-in was denied in the browser"},
		"http error":         {http.StatusBadGateway, "bad gateway", "device authorization: HTTP 502: bad gateway"},
		"empty answer":       {http.StatusOK, `{}`, "device authorization: unexpected response"},
		"not json":           {http.StatusOK, "<html>", "device authorization: unexpected response"},
		"proof rejected": {
			http.StatusBadRequest, `{"error":"invalid_dpop_proof"}`,
			"sign-in failed, Nokku rejected this machine's proof. Check that the clock is right and run nk login again",
		},
		"nonce rejected twice": {
			http.StatusBadRequest, `{"error":"use_dpop_nonce"}`,
			"sign-in failed, Nokku rejected the retry with a fresh nonce, run nk login again",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)
			c := &Client{State: &state.State{APIURL: srv.URL}, httpc: srv.Client()}

			_, _, err := c.pollDeviceToken(t.Context(), "dev", 1)
			require.EqualError(t, err, tc.want)
		})
	}
}

// A stale nonce is retried at once, the fresh one came with the rejection.
func TestPollDeviceTokenRetriesNonceWithoutWaiting(t *testing.T) {
	t.Parallel()
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if polls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadRequest)
			writeOAuthErr(w, "use_dpop_nonce")
			return
		}
		writeJSON(w, map[string]any{"access_token": "tok", "expires_in": 60})
	}))
	t.Cleanup(srv.Close)
	c := &Client{State: &state.State{APIURL: srv.URL}, httpc: srv.Client()}

	start := time.Now()
	token, expiresIn, err := c.pollDeviceToken(t.Context(), "dev", 30)
	require.NoError(t, err)
	assert.Equal(t, "tok", token)
	assert.Equal(t, 60, expiresIn)
	assert.EqualValues(t, 2, polls.Load())
	assert.Less(t, time.Since(start), 5*time.Second, "the retry waited for the poll interval")
}

// A refused proof, like one from a wrong clock, ends the login. No other URL is tried.
func TestPollDeviceTokenGivesUpOnARejectedProof(t *testing.T) {
	t.Parallel()
	var polls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/device/nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("DPoP-Nonce", "n")
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /auth/device/token", func(w http.ResponseWriter, _ *http.Request) {
		polls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		writeOAuthErr(w, "invalid_dpop_proof")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := &Client{State: &state.State{APIURL: srv.URL}, httpc: srv.Client()}
	c.dpop = dpopclient.New(newTestProofer(t), srv.Client(), func() string { return "" },
		dpopclient.Options{BaseURL: srv.URL})

	_, _, err := c.pollDeviceToken(t.Context(), "dev", 30)
	require.ErrorContains(t, err, "Check that the clock is right")
	assert.EqualValues(t, 1, polls.Load(), "a rejected proof is final")
}

// A proof only verifies for the URL the server knows itself by, so a login through another URL stops at once.
func TestDeviceLoginRefusesAServerAtAnotherURL(t *testing.T) {
	f, srv := newFakeDeviceFlow(t)
	f.baseURL = "https://nokku.example.com"
	c := &Client{State: &state.State{APIURL: srv.URL}, httpc: srv.Client()}
	c.dpop = dpopclient.New(newTestProofer(t), srv.Client(), func() string { return "" },
		dpopclient.Options{BaseURL: srv.URL})

	err := c.deviceLogin(t.Context())
	require.ErrorIs(t, err, dpopclient.ErrAPIURLMismatch)
	require.ErrorContains(t, err, "https://nokku.example.com", "the error names the URL to use")
	assert.Empty(t, f.grants, "no device flow was started")
}

// The code and the link are printed, and the answer is read into memory.
func TestDeviceAuthRejectsHostileAnswers(t *testing.T) {
	t.Parallel()
	const valid = `{"device_code":"d","user_code":"AB-CD","verification_uri":"https://a.example/device"}`
	for name, tc := range map[string]struct {
		body string
		ok   bool
	}{
		"a plain answer": {valid, true},
		"escape sequence in the code": {
			`{"device_code":"d","user_code":"AB\u001b[2JCD","verification_uri":"https://a.example/device"}`, false,
		},
		"escape sequence in the link": {
			`{"device_code":"d","user_code":"AB-CD","verification_uri":"https://a.example/\u009b2J"}`, false,
		},
		"answer past the size cap": {strings.Repeat(" ", maxDeviceResponse) + valid, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)
			c := &Client{State: &state.State{APIURL: srv.URL}, httpc: srv.Client()}

			_, err := c.beginDeviceAuth(t.Context())
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
		})
	}
}
