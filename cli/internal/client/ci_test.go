package client

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokku/internal/dpop"

	"github.com/nokku-sh/nokku/cli/internal/state"
)

const fakeJobToken = "head.body.sig"

// fakeExchange is the core's side of nk login --ci.
type fakeExchange struct {
	nokkuv1connect.UnimplementedAuthServiceHandler

	expiresAt time.Time
	err       error
	got       *nokkuv1.ExchangeWorkloadTokenRequest
	calls     int
}

// signingExchange answers a stale nonce with a fresh one, like the core.
type signingExchange struct {
	nokkuv1connect.UnimplementedAuthServiceHandler

	verify func(h http.Header, token string) (string, error)
	nonce  func() string
}

func clearJobEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{"ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "NK_ID_TOKEN"} {
		t.Setenv(name, "")
	}
}

func TestJobTokenFromGitHubActions(t *testing.T) {
	const audience = "https://nokku.example.com"
	clearJobEnv(t)
	// Like a runner's token endpoint, checking what a real one needs.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "bearer request-token", r.Header.Get("Authorization"))
		assert.Equal(t, audience, r.URL.Query().Get("audience"))
		assert.Equal(t, "2.0", r.URL.Query().Get("api-version"), "the query the runner gave must stay")
		_, _ = w.Write([]byte(`{"count":1,"value":"` + fakeJobToken + `"}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL+"/token?api-version=2.0")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token")
	t.Setenv("NK_ID_TOKEN", "the platform asked first wins over this")

	got, err := jobToken(t.Context(), audience)
	require.NoError(t, err)
	assert.Equal(t, fakeJobToken, got)
}

func TestJobTokenRefusesABadGitHubAnswer(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"no permission": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) },
		"no token":      func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"count":0}`)) },
		"no JSON":       func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`<html>`)) },
	} {
		t.Run(name, func(t *testing.T) {
			clearJobEnv(t)
			srv := httptest.NewServer(handler)
			t.Cleanup(srv.Close)
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL)
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token")
			_, err := jobToken(t.Context(), "https://nokku.example.com")
			require.ErrorContains(t, err, "GitHub Actions")
			assert.NotContains(t, err.Error(), "request-token")
		})
	}
}

func TestJobTokenFromTheEnvironment(t *testing.T) {
	clearJobEnv(t)
	t.Setenv("NK_ID_TOKEN", " "+fakeJobToken+"\n")
	got, err := jobToken(t.Context(), "https://nokku.example.com")
	require.NoError(t, err)
	assert.Equal(t, fakeJobToken, got)
}

func TestJobTokenSaysWhatToSet(t *testing.T) {
	clearJobEnv(t)
	_, err := jobToken(t.Context(), "https://nokku.example.com")
	require.Error(t, err)
	for _, hint := range []string{"id-token: write", "NK_ID_TOKEN", "id_tokens"} {
		assert.ErrorContains(t, err, hint)
	}
}

func (f *fakeExchange) ExchangeWorkloadToken(
	_ context.Context,
	req *nokkuv1.ExchangeWorkloadTokenRequest,
) (*nokkuv1.ExchangeWorkloadTokenResponse, error) {
	f.calls++
	f.got = req
	if f.err != nil {
		return nil, f.err
	}
	return &nokkuv1.ExchangeWorkloadTokenResponse{
		AccessToken: new("nk_sa_session"),
		ExpiresAt:   timestamppb.New(f.expiresAt),
	}, nil
}

func newCIClient(t *testing.T, core *fakeExchange, s *state.State) *Client {
	t.Helper()
	setTestDirs(t)
	clearJobEnv(t)
	t.Setenv("NK_ID_TOKEN", fakeJobToken)
	mux := http.NewServeMux()
	server := connect.NewServer()
	nokkuv1connect.RegisterAuthServiceHandler(server, core)
	connecthttp.Mount(mux, server)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	s.APIURL = srv.URL
	return &Client{
		State: s,
		httpc: srv.Client(),
		auth: nokkuv1connect.NewAuthServiceClient(
			connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL)),
		),
	}
}

func TestLoginCISavesTheSession(t *testing.T) {
	core := &fakeExchange{expiresAt: time.Now().Add(time.Hour).Truncate(time.Second)}
	c := newCIClient(t, core, &state.State{})

	require.NoError(t, c.LoginCI(t.Context(), "deploy"))
	assert.Equal(t, "deploy", core.got.GetServiceAccount())
	assert.Equal(t, fakeJobToken, core.got.GetToken())
	assert.Equal(t, "nk_sa_session", c.State.SessionToken)
	assert.True(t, core.expiresAt.Equal(c.State.SessionExpiresAt))

	saved := state.Load()
	assert.Equal(t, "nk_sa_session", saved.SessionToken, "a later nk run reads the session from disk")
	assert.True(t, saved.CIJob(), "a later nk run must know this is a job")
}

// A proof goes out through dial's client, nothing of the old session does.
func TestLoginCISignsTheExchange(t *testing.T) {
	setTestDirs(t)
	clearJobEnv(t)
	t.Setenv("NK_ID_TOKEN", fakeJobToken)

	verifier := dpop.NewVerifier([]byte("nonce-key"), func([32]byte) bool { return true }, time.Now)
	var htu string
	var jobTokens []string
	core := &signingExchange{verify: func(h http.Header, token string) (string, error) {
		jobTokens = append(jobTokens, token)
		assert.Empty(t, h.Get("Authorization"), "the old session went along")
		return verifier.Verify(h.Get("DPoP"), "", http.MethodPost,
			htu+nokkuv1connect.AuthServiceExchangeWorkloadTokenProcedure, "")
	}, nonce: verifier.CurrentNonce}
	mux := http.NewServeMux()
	server := connect.NewServer()
	nokkuv1connect.RegisterAuthServiceHandler(server, core)
	connecthttp.Mount(mux, server)
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	htu = srv.URL

	c := &Client{proofer: newTestProofer(t), State: &state.State{
		APIURL:       srv.URL,
		APICA:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})),
		SessionToken: "old",
	}}
	require.NoError(t, c.dial())

	require.NoError(t, c.LoginCI(t.Context(), "deploy"))
	assert.Equal(t, "nk_sa_session", c.State.SessionToken)
	assert.Equal(
		t,
		[]string{fakeJobToken, fakeJobToken},
		jobTokens,
		"the nonce round repeats the call, the core spent nothing",
	)
}

func (s *signingExchange) ExchangeWorkloadToken(
	ctx context.Context,
	req *nokkuv1.ExchangeWorkloadTokenRequest,
) (*nokkuv1.ExchangeWorkloadTokenResponse, error) {
	info, ok := connect.CallInfoForServerContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal, "no call info")
	}
	h := http.Header{}
	for _, name := range []string{"Authorization", "DPoP"} {
		if v := info.RequestHeader().Get(name); v != "" {
			h.Set(name, v)
		}
	}
	jkt, err := s.verify(h, req.GetToken())
	if errors.Is(err, dpop.ErrNonce) {
		info.ResponseHeader().Set("DPoP-Nonce", s.nonce())
		return nil, connect.NewError(connect.CodeUnauthenticated, "stale DPoP nonce")
	}
	if err != nil || jkt == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, "no valid proof")
	}
	return &nokkuv1.ExchangeWorkloadTokenResponse{
		AccessToken: new("nk_sa_session"),
		ExpiresAt:   timestamppb.New(time.Now().Add(time.Hour)),
	}, nil
}

// A person's snapshot next to a job's session would name the wrong subject.
func TestLoginCIReplacesThePersonInTheCache(t *testing.T) {
	c := newCIClient(t, &fakeExchange{expiresAt: time.Now().Add(time.Hour)}, &state.State{
		User: &state.User{ID: "u"}, Targets: []state.Target{{ID: targetID}},
	})
	require.NoError(t, c.LoginCI(t.Context(), "deploy"))
	assert.Nil(t, c.State.User)
	assert.Empty(t, c.State.Targets)
}

func TestLoginCIRefusals(t *testing.T) {
	core := &fakeExchange{}
	c := newCIClient(t, core, &state.State{})

	require.ErrorContains(t, c.LoginCI(t.Context(), ""), "name of a service account")
	c.State.Token = "nk_sa_key"
	require.ErrorContains(t, c.LoginCI(t.Context(), "deploy"), "NK_TOKEN")
	assert.Zero(t, core.calls, "a call went out")
}

func TestLoginCIKeepsTheOldSessionOnARefusal(t *testing.T) {
	core := &fakeExchange{err: connect.NewError(connect.CodeUnauthenticated, "refused")}
	c := newCIClient(t, core, &state.State{SessionToken: "old"})

	err := c.LoginCI(t.Context(), "deploy")
	require.ErrorContains(t, err, "deploy")
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	assert.Equal(t, "old", c.State.SessionToken)
	assert.Equal(t, 1, core.calls, "a job token works once, nk must not send it again")
}

// ciState's session ran out. A device flow would end in another error.
func ciState() *state.State {
	s := &state.State{}
	s.SessionToken = "nk_sa_session"
	s.SessionExpiresAt = time.Now().Add(-time.Minute)
	s.ServiceAccount = &state.ServiceAccount{ID: "sa", Name: "deploy"}
	return s
}

func TestEndedCISessionNeverOpensABrowser(t *testing.T) {
	for name, interactive := range map[string]bool{"nk login": true, "nk proxy": false} {
		t.Run(name, func(t *testing.T) {
			setTestDirs(t)
			c := newSyncTestClient(t, &fakeCore{})
			c.State.Config, c.State.Cache = ciState().Config, ciState().Cache

			require.ErrorIs(t, c.Sync(t.Context(), interactive), ErrCISessionEnded)
		})
	}
}

func TestRejectedCISessionNeverOpensABrowser(t *testing.T) {
	for name, interactive := range map[string]bool{"nk login": true, "nk proxy": false} {
		t.Run(name, func(t *testing.T) {
			setTestDirs(t)
			core := &fakeCore{
				accessErr: connect.NewError(connect.CodeUnauthenticated, assert.AnError.Error()).
					WithCause(assert.AnError),
			}
			c := newSyncTestClient(t, core)
			c.State.ServiceAccount = &state.ServiceAccount{ID: "sa", Name: "deploy"}

			require.ErrorIs(t, c.Sync(t.Context(), interactive), ErrCISessionEnded)
			assert.Equal(t, "sess-token", c.State.SessionToken)
		})
	}
}

// The cache hides an outage, not an ended session. A job stops with the reason.
func TestEndedCISessionSkipsTheCache(t *testing.T) {
	setTestDirs(t)
	c := newSyncTestClient(t, &fakeCore{})
	c.State.Config, c.State.Cache = ciState().Config, ciState().Cache
	c.State.Targets = []state.Target{{ID: targetID, Usernames: []string{"deploy"}}}
	c.State.Server = c.State.APIURL
	require.NoError(t, c.State.Save())

	require.ErrorIs(t, c.SyncOrCache(t.Context(), false), ErrCISessionEnded)
}

func TestEnsureCertNamesAnEndedCISession(t *testing.T) {
	setTestDirs(t)
	core := &fakeCore{
		sign: func(*nokkuv1.SignSSHCertificateRequest) (*nokkuv1.SignSSHCertificateResponse, error) {
			return nil, connect.NewError(connect.CodeUnauthenticated, assert.AnError.Error()).WithCause(assert.AnError)
		},
	}
	c := newSyncTestClient(t, core)
	c.State.ServiceAccount = &state.ServiceAccount{ID: "sa", Name: "deploy"}
	ca := newFakeCA(t)
	setupKey(t)

	err := c.EnsureCert(t.Context(), state.Target{ID: targetID}, state.CA{PublicKey: ca.pubKey})
	require.ErrorIs(t, err, ErrCISessionEnded)
}
