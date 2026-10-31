//go:build integration

package api_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/api"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

const sessionCookie = "nokku_session"

// inbox holds the links the server would have mailed, by address.
type inbox struct {
	mu    sync.Mutex
	links map[string][]string
}

func (b *inbox) put(to, link string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.links[to] = append(b.links[to], link)
}

// next waits for the first link mailed to to. Sign-in links are mailed from a goroutine.
func (b *inbox) next(t *testing.T, to string) string {
	t.Helper()
	var link string
	require.Eventually(t, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		if got := b.links[to]; len(got) > 0 {
			link, b.links[to] = got[0], got[1:]
			return true
		}
		return false
	}, 10*time.Second, 10*time.Millisecond, "nothing was mailed to %s", to)
	return link
}

// mailServer serves base with mail on. Links iam would mail land in the inbox, the API's own mails go nowhere.
func mailServer(t *testing.T, base *config.Config) (*config.Config, *httptest.Server, *inbox) {
	t.Helper()
	box := &inbox{links: map[string][]string{}}
	mailer := *base.Email
	mailer.SMTPHost = "smtp.invalid"
	local := *base
	local.Email = &mailer
	cfg, srv := iamServer(t, &local, iam.Deps{
		SendMagicLink: func(_ context.Context, _, email, link string, _ time.Duration) error {
			box.put(email, link)
			return nil
		},
		SendInvite: func(_ context.Context, email, _, _, link string, _ time.Duration) error {
			box.put(email, link)
			return nil
		},
	})
	return cfg, srv, box
}

// iamServer serves base with an iam of its own, whose seat cap is the one of base. mail holds the mail functions.
func iamServer(t *testing.T, base *config.Config, mail iam.Deps) (*config.Config, *httptest.Server) {
	t.Helper()
	mail.Conn = base.Conn
	mail.Keyset = base.Keyset
	mail.Audit = base.Audit
	mail.Secure = strings.HasPrefix(base.FullURL(), "https://")
	mail.CanJoin = base.Entitlements.CanInvite
	mail.StrictEmail = base.SaaS
	local := *base
	var err error
	local.IAM, err = iam.New(t.Context(), mail)
	require.NoError(t, err)
	srv := httptest.NewServer(api.New(&local).Handler(t.Context()))
	t.Cleanup(srv.Close)
	return &local, srv
}

// login is a session as its client holds it. The browser has a cookie, nk a token bound to its key.
type login struct {
	token string
	key   *ecdsa.PrivateKey
}

// browserSession is a cookie session of u, signed in age ago.
func browserSession(t *testing.T, cfg *config.Config, u *db.User, age time.Duration) login {
	t.Helper()
	tok, token, err := cfg.IAM.IssueToken(wsCtx(t, cfg), iam.TokenParams{
		SubjectID: u.ID,
		Kind:      actor.KindUser,
		Method:    iam.MethodPasskey,
	})
	require.NoError(t, err)
	if age > 0 {
		ageSession(t, tok.ID, age)
	}
	return login{token: token}
}

func ageSession(t *testing.T, id string, age time.Duration) {
	t.Helper()
	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	defer func() { _ = owner.Close(t.Context()) }()
	tag, err := owner.Exec(t.Context(),
		"UPDATE access_tokens SET created_at = now() - make_interval(secs => $2) WHERE id = $1", id, age.Seconds())
	require.NoError(t, err)
	require.Equal(t, int64(1), tag.RowsAffected())
}

// sessionAfter tells whether the session still signs in.
func sessionAfter(t *testing.T, cfg *config.Config, token string) string {
	t.Helper()
	if _, _, err := cfg.IAM.AuthenticateToken(wsCtx(t, cfg), token, accessTokens...); err != nil {
		return "session ended"
	}
	return "session kept"
}

// signedIn sends s on every unary call the way its client does. Each call of nk carries a new proof.
func signedIn(t *testing.T, cfg *config.Config, s login) connect.ClientInterceptor {
	t.Helper()
	return func(next connect.ClientFunc) connect.ClientFunc {
		return func(ctx context.Context, spec connect.Spec) (connect.ClientStream, error) {
			if info, ok := connect.CallInfoForClientContext(ctx); ok && spec.StreamType == connect.StreamTypeUnary {
				h := info.RequestHeader()
				if s.key == nil {
					h.Set("Cookie", sessionCookie+"="+s.token)
				} else {
					h.Set("Authorization", "DPoP "+s.token)
					h.Set("DPoP", dpopProof(t, cfg, s.key, spec.Procedure, s.token))
				}
			}
			return next(ctx, spec)
		}
	}
}

func rpcAnswer(err error) string {
	if err == nil {
		return "ok"
	}
	if ce, ok := errors.AsType[*connect.Error](err); ok {
		return ce.Code().String() + ": " + ce.Message()
	}
	return "error: " + err.Error()
}

// reply is what a plain HTTP route answered. Redirects are not followed.
type reply struct {
	status   int
	location string
	body     map[string]any
}

// String is the status and the message of the body, never a token it carries.
func (r reply) String() string {
	for _, key := range []string{"message", "error", "detail"} {
		if msg, ok := r.body[key].(string); ok {
			return fmt.Sprintf("%d %s", r.status, msg)
		}
	}
	return strconv.Itoa(r.status)
}

func send(t *testing.T, srv *httptest.Server, method, path string, form url.Values, set func(http.Header)) reply {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, body)
	require.NoError(t, err)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("User-Agent", "nk/test (linux/amd64)")
	if set != nil {
		set(req.Header)
	}
	client := *srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	out := reply{status: resp.StatusCode, location: resp.Header.Get("Location")}
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = json.Unmarshal(raw, &out.body)
	return out
}

func withCookie(token string) func(http.Header) {
	return func(h http.Header) { h.Set("Cookie", sessionCookie+"="+token) }
}

type deviceGrant struct {
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
}

func startDevice(t *testing.T, srv *httptest.Server) deviceGrant {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/auth/device", nil)
	require.NoError(t, err)
	req.Header.Set("User-Agent", "nk/test (linux/amd64)")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var grant deviceGrant
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&grant))
	return grant
}

func pollDevice(
	t *testing.T,
	cfg *config.Config,
	srv *httptest.Server,
	deviceCode string,
	key *ecdsa.PrivateKey,
) reply {
	t.Helper()
	const path = "/auth/device/token"
	return send(t, srv, http.MethodPost, path, url.Values{"device_code": {deviceCode}}, func(h http.Header) {
		h.Set("DPoP", dpopProof(t, cfg, key, path, ""))
	})
}

// deviceLogin signs nk in as u through the device flow, approved by a browser session of u.
func deviceLogin(t *testing.T, cfg *config.Config, srv *httptest.Server, u *db.User) login {
	t.Helper()
	grant := startDevice(t, srv)
	approver := browserSession(t, cfg, u, 0)
	approved := send(t, srv, http.MethodPost, "/auth/device/verify",
		url.Values{"user_code": {grant.UserCode}}, withCookie(approver.token))
	require.Equal(t, http.StatusOK, approved.status, approved.String())
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	polled := pollDevice(t, cfg, srv, grant.DeviceCode, key)
	require.Equal(t, http.StatusOK, polled.status, polled.String())
	token, _ := polled.body["access_token"].(string)
	require.NotEmpty(t, token)
	return login{token: token, key: key}
}
