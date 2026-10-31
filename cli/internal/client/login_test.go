package client

import (
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
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/nokku-sh/nokku/internal/dpop"
	"github.com/nokku-sh/nokku/internal/dpopclient"

	"github.com/nokku-sh/nokku/cli/internal/state"
)

const testAPI = "https://nokku.example.com"

// fakeDeviceFlow mirrors iam.DeviceFlow closely enough for the poll loop, DPoP checks and replay store included.
type fakeDeviceFlow struct {
	mu         sync.Mutex
	grants     map[string]*fakeGrant // by device code
	replay     map[string]bool
	nonce      string
	baseURL    string
	expiresIn  int
	violations map[string]int
	lastPoll   map[string]time.Time
}

type fakeGrant struct {
	deviceCode string
	userCode   string
	status     string
	userAgent  string
}

func newFakeDeviceFlow() (*fakeDeviceFlow, http.Handler) {
	f := &fakeDeviceFlow{
		grants:     map[string]*fakeGrant{},
		replay:     map[string]bool{},
		nonce:      "test-nonce",
		baseURL:    testAPI,
		expiresIn:  900,
		lastPoll:   map[string]time.Time{},
		violations: map[string]int{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/device", f.begin)
	mux.HandleFunc("POST /auth/device/token", f.poll)
	mux.HandleFunc("GET /auth/device/nonce", f.nonceEndpoint)
	return f, mux
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
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               g.deviceCode,
		"user_code":                 g.userCode,
		"verification_uri":          f.baseURL + "/device",
		"verification_uri_complete": f.baseURL + "/device?user_code=" + g.userCode,
		"expires_in":                f.expiresIn,
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
		// tooFast: the required interval grows by 5s with each poll that came too soon.
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
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "tok-for-" + jkt,
			"token_type":   "DPoP",
			"expires_in":   60,
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
		return "", "use_dpop_nonce"
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(proof, ".")[1])
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
	if claims.HTM != http.MethodPost || !strings.EqualFold(claims.HTU, f.baseURL+"/auth/device/token") {
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
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// inMemory serves requests without a socket, so the fake clock of a synctest bubble runs the poll interval at once.
type inMemory struct{ h http.Handler }

func (m inMemory) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	m.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

func newTestProofer(t *testing.T) *dpop.Proofer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p, err := dpop.NewProofer(key)
	require.NoError(t, err)
	return p
}

// testClient talks to h at testAPI, signing like nk does.
func testClient(t *testing.T, h http.Handler) *Client {
	t.Helper()
	c := &Client{State: &state.State{APIURL: testAPI}, httpc: &http.Client{Transport: inMemory{h}}}
	c.dpop = dpopclient.New(newTestProofer(t), c.httpc, func() string { return c.State.SessionToken },
		dpopclient.Options{BaseURL: testAPI})
	return c
}

// runDeviceLogin runs deviceLogin without the browser and approves after a few polls, like a user clicking accept.
func runDeviceLogin(t *testing.T, c *Client, f *fakeDeviceFlow) (string, error) {
	t.Helper()
	ctx, cfg, err := c.deviceFlow(t.Context())
	require.NoError(t, err)
	d, err := beginDeviceAuth(ctx, cfg)
	require.NoError(t, err)

	go func() {
		time.Sleep(3 * time.Second)
		f.approve(d.DeviceCode)
	}()
	tok, err := pollDeviceToken(ctx, cfg, d)
	if err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}

func TestDeviceFlowTwoConsecutiveLogins(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, h := newFakeDeviceFlow()
		c := testClient(t, h)

		for i := range 2 {
			token, err := runDeviceLogin(t, c, f)
			require.NoError(t, err, "login %d", i+1)
			assert.Equal(t, "tok-for-jkt", token, "login %d", i+1)
		}

		// The approval page shows who asked, so the request has to say it is nk.
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, g := range f.grants {
			assert.True(t, strings.HasPrefix(g.userAgent, "nk/"), "device request user agent = %q", g.userAgent)
		}
	})
}

// RFC 8628 section 3.5: each slow_down adds 5 seconds to this and every later poll.
func TestDeviceFlowSlowsDown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var polls []time.Time
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/auth/device/token" {
				writeJSON(w, http.StatusOK, map[string]any{
					"device_code": "d", "user_code": "AB-CD", "verification_uri": testAPI + "/device", "interval": 1,
				})
				return
			}
			polls = append(polls, time.Now())
			switch len(polls) {
			case 1:
				writeOAuthErr(w, "slow_down")
			case 2:
				writeOAuthErr(w, "authorization_pending")
			default:
				writeJSON(w, http.StatusOK, map[string]any{"access_token": "tok"})
			}
		})
		c := &Client{State: &state.State{APIURL: testAPI}, httpc: &http.Client{Transport: inMemory{h}}}
		ctx, cfg, err := c.deviceFlow(t.Context())
		require.NoError(t, err)
		d, err := beginDeviceAuth(ctx, cfg)
		require.NoError(t, err)
		start := time.Now()

		tok, err := pollDeviceToken(ctx, cfg, d)
		require.NoError(t, err)
		assert.Equal(t, "tok", tok.AccessToken)
		require.Len(t, polls, 3)
		assert.Equal(t, time.Second, polls[0].Sub(start))
		assert.Equal(t, 6*time.Second, polls[1].Sub(polls[0]), "slow_down did not add 5 seconds")
		assert.Equal(t, 6*time.Second, polls[2].Sub(polls[1]), "the slower pace did not stick")
	})
}

// The code runs out after expires_in, so the poll ends then even if the server never says so.
func TestDeviceFlowExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, h := newFakeDeviceFlow()
		f.expiresIn = 30
		c := testClient(t, h)
		ctx, cfg, err := c.deviceFlow(t.Context())
		require.NoError(t, err)
		d, err := beginDeviceAuth(ctx, cfg)
		require.NoError(t, err)
		start := time.Now()

		_, err = pollDeviceToken(ctx, cfg, d)
		require.EqualError(t, err, "sign-in code expired, run nk login again")
		assert.Equal(t, 30*time.Second, time.Since(start))
	})
}

// The OS opener also launches files and custom schemes, so a core may only send a web page.
func TestDeviceFlowRejectsNonWebLink(t *testing.T) {
	f, h := newFakeDeviceFlow()
	f.baseURL = "file:///etc/passwd"
	c := testClient(t, h)
	// The fake names the file URL as its own, so only the link check can stop it.
	c.dpop = nil

	ctx, cfg, err := c.deviceFlow(t.Context())
	require.NoError(t, err)
	_, err = beginDeviceAuth(ctx, cfg)
	require.ErrorContains(t, err, "not a web address")
}

// pollAnswers runs the poll against a token endpoint that gives the answers in turn, the last one for good.
func pollAnswers(t *testing.T, answers ...func(w http.ResponseWriter)) (int32, error) {
	t.Helper()
	var polls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/device/nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("DPoP-Nonce", "n")
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /auth/device/token", func(w http.ResponseWriter, _ *http.Request) {
		n := int(polls.Add(1))
		answers[min(n, len(answers))-1](w)
	})
	c := testClient(t, mux)
	ctx, cfg, err := c.deviceFlow(t.Context())
	require.NoError(t, err)
	_, err = pollDeviceToken(ctx, cfg, &oauth2.DeviceAuthResponse{DeviceCode: "dev", Interval: 1})
	return polls.Load(), err
}

func answer(status int, body string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// Waiting cannot fix any of these answers, so the poll ends on them.
func TestPollDeviceTokenStopsOnFinalAnswers(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
		want   string
	}{
		"denied":             {http.StatusBadRequest, `{"error":"access_denied"}`, "sign-in was denied in the browser"},
		"expired":            {http.StatusBadRequest, `{"error":"expired_token"}`, "sign-in code expired, run nk login again"},
		"unknown code":       {http.StatusBadRequest, `{"error":"server_error"}`, "device authorization failed: server_error"},
		"oauth error on 200": {http.StatusOK, `{"error":"access_denied"}`, "sign-in was denied in the browser"},
		"http error":         {http.StatusForbidden, "forbidden", "device authorization: HTTP 403: forbidden"},
		"empty answer": {
			http.StatusOK, `{}`, "device authorization: oauth2: server response missing access_token",
		},
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
			synctest.Test(t, func(t *testing.T) {
				_, err := pollAnswers(t, answer(tc.status, tc.body))
				require.EqualError(t, err, tc.want)
			})
		})
	}
}

func TestPollDeviceTokenOutlastsABlip(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		polls, err := pollAnswers(t,
			answer(http.StatusServiceUnavailable, ""),
			answer(http.StatusOK, `{"access_token":"tok"}`),
		)
		require.NoError(t, err, "one 503 ended the sign-in")
		assert.EqualValues(t, 2, polls)
	})
}

func TestPollDeviceTokenGivesUpOnAServerThatStaysDown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		polls, err := pollAnswers(t, answer(http.StatusBadGateway, "bad gateway"))
		require.EqualError(t, err, "device authorization: HTTP 502: bad gateway")
		assert.EqualValues(t, pollRetries+1, polls)
	})
}

// A stale nonce is retried at once, the fresh one came with the rejection.
func TestPollDeviceTokenRetriesNonceWithoutWaiting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		polls, err := pollAnswers(t,
			answer(http.StatusBadRequest, `{"error":"use_dpop_nonce"}`),
			answer(http.StatusOK, `{"access_token":"tok","expires_in":60}`),
		)
		require.NoError(t, err)
		assert.EqualValues(t, 2, polls)
		assert.Equal(t, time.Second, time.Since(start), "the retry waited for the poll interval")
	})
}

// A refused proof, like one from a wrong clock, ends the login. No other URL is tried.
func TestPollDeviceTokenGivesUpOnARejectedProof(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		polls, err := pollAnswers(t, answer(http.StatusBadRequest, `{"error":"invalid_dpop_proof"}`))
		require.ErrorContains(t, err, "Check that the clock is right")
		assert.EqualValues(t, 1, polls, "a rejected proof is final")
	})
}

// A proof only verifies for the URL the server knows itself by, so a login through another URL stops at once.
func TestDeviceLoginRefusesAServerAtAnotherURL(t *testing.T) {
	f, h := newFakeDeviceFlow()
	f.baseURL = "https://other.example.com"
	c := testClient(t, h)

	err := c.deviceLogin(t.Context())
	require.ErrorIs(t, err, dpopclient.ErrAPIURLMismatch)
	require.ErrorContains(t, err, "https://other.example.com", "the error names the URL to use")
	assert.Empty(t, f.grants, "no device flow was started")
}

// The code and the link are printed, and the answer is read into memory.
func TestDeviceAuthRejectsHostileAnswers(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		body string
		ok   bool
	}{
		"a plain answer": {`{"device_code":"d","user_code":"AB-CD","verification_uri":"https://a.example/device"}`, true},
		"escape sequence in the code": {
			`{"device_code":"d","user_code":"AB\u001b[2JCD","verification_uri":"https://a.example/device"}`, false,
		},
		"escape sequence in the link": {
			`{"device_code":"d","user_code":"AB-CD","verification_uri":"https://a.example/\u009b2J"}`, false,
		},
		"no code": {`{"device_code":"d","verification_uri":"https://a.example/device"}`, false},
		"answer past the size cap": {
			strings.Repeat(" ", maxDeviceResponse) +
				`{"device_code":"d","user_code":"AB-CD","verification_uri":"https://a.example/device"}`,
			false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				answer(http.StatusOK, tc.body)(w)
			})
			c := &Client{State: &state.State{APIURL: testAPI}, httpc: &http.Client{Transport: inMemory{h}}}
			ctx, cfg, err := c.deviceFlow(t.Context())
			require.NoError(t, err)

			_, err = beginDeviceAuth(ctx, cfg)
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
		})
	}
}
