//go:build integration

package api_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect/v2"
	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokku/internal/dpop"
	"github.com/nokku-sh/nokku/internal/dpopclient"

	"github.com/nokku-sh/nokku/core/internal/api"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
)

const (
	jobSubject = "repo:acme/app:ref:refs/heads/main"
	exchange   = nokkuv1connect.AuthServiceExchangeWorkloadTokenProcedure
	refusedAs  = "unauthenticated: this job can't sign in as this service account. Check its name and the issuer of " +
		"its rules, the audit log says why for a token its issuer signed"
)

// jobIssuer is a CI platform: discovery and keys over https, a token per job.
type jobIssuer struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

type federation struct {
	cfg      *config.Config
	srv      *httptest.Server
	accounts nokkuv1connect.ServiceAccountServiceClient
	issuer   *jobIssuer
	account  *nokkuv1.ServiceAccount
	rule     *nokkuv1.ServiceAccountFederation
	key      *ecdsa.PrivateKey
}

func newJobIssuer(t *testing.T) *jobIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	j := &jobIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                j.url(),
			"jwks_uri":                              j.url() + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: key.Public(), KeyID: "job", Algorithm: "RS256", Use: "sig"},
		}})
	})
	j.srv = httptest.NewTLSServer(mux)
	t.Cleanup(j.srv.Close)
	return j
}

func (j *jobIssuer) url() string { return j.srv.URL }

// claims are a job the fixture's rule takes. A test changes what it is about.
func (j *jobIssuer) claims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":           j.url(),
		"aud":           testWorkspace.BaseURL,
		"sub":           jobSubject,
		"exp":           now.Add(10 * time.Minute).Unix(),
		"iat":           now.Unix(),
		"jti":           uuid.New().String(),
		"repository_id": "74",
		"run_id":        42,
	}
}

func (j *jobIssuer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: j.key, KeyID: "job"}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)
	jws, err := signer.Sign(payload)
	require.NoError(t, err)
	raw, err := jws.CompactSerialize()
	require.NoError(t, err)
	return raw
}

func dpopKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// newFederation is a limited account with a rule that takes jobIssuer.claims.
func newFederation(t *testing.T) *federation {
	t.Helper()
	cfg, srv := newTestAPI(t)
	admin := header("Authorization",
		"Bearer "+seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN))
	f := &federation{
		cfg: cfg,
		srv: srv,
		accounts: nokkuv1connect.NewServiceAccountServiceClient(
			clientOn(srv, admin),
		),
		issuer: newJobIssuer(t),
		key:    dpopKey(t),
	}
	f.account = f.addAccount(t)
	f.rule = f.addRule(t, f.account, map[string]string{"sub": jobSubject})
	return f
}

func (f *federation) addAccount(t *testing.T) *nokkuv1.ServiceAccount {
	t.Helper()
	created, err := f.accounts.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
		Name:          new(uniq("ci")),
		ForceCommand:  new("/usr/local/bin/deploy"),
		SourceAddress: new("198.51.100.0/24"),
	})
	require.NoError(t, err)
	return created.GetServiceAccount()
}

func (f *federation) addRule(
	t *testing.T,
	account *nokkuv1.ServiceAccount,
	claims map[string]string,
) *nokkuv1.ServiceAccountFederation {
	t.Helper()
	added, err := f.accounts.AddServiceAccountFederation(t.Context(), &nokkuv1.AddServiceAccountFederationRequest{
		ServiceAccountId: account.Id,
		Issuer:           new(f.issuer.url()),
		Claims:           claims,
	})
	require.NoError(t, err)
	return added.GetFederation()
}

func (f *federation) exchange(
	t *testing.T,
	name, token string,
	interceptors ...connect.ClientInterceptor,
) (*nokkuv1.ExchangeWorkloadTokenResponse, error) {
	t.Helper()
	return nokkuv1connect.NewAuthServiceClient(
		clientOn(f.srv, interceptors...),
	).ExchangeWorkloadToken(t.Context(), &nokkuv1.ExchangeWorkloadTokenRequest{ServiceAccount: &name, Token: &token})
}

func (f *federation) proof(t *testing.T) connect.ClientInterceptor {
	t.Helper()
	return header("DPoP", dpopProof(t, f.cfg, f.key, exchange, ""))
}

func (f *federation) signIn(t *testing.T) (*nokkuv1.ExchangeWorkloadTokenResponse, login) {
	t.Helper()
	res, err := f.exchange(t, f.account.GetName(), f.issuer.sign(t, f.issuer.claims()), f.proof(t))
	require.NoError(t, err)
	return res, login{token: res.GetAccessToken(), key: f.key}
}

// whoami answers the id of the account a session signs in as.
func (f *federation) whoami(t *testing.T, s connect.ClientInterceptor) (string, error) {
	t.Helper()
	res, err := nokkuv1connect.NewTargetServiceClient(
		clientOn(f.srv, s),
	).GetSubjectAccess(t.Context(), &nokkuv1.GetSubjectAccessRequest{})
	return res.GetServiceAccount().GetId(), err
}

// exchangeRows are the audit rows of exchanges, the newest first.
func (f *federation) exchangeRows(t *testing.T) []*db.ListAuditLogsRow {
	t.Helper()
	var rows []*db.ListAuditLogsRow
	require.NoError(t, f.cfg.Conn.TenantTx(wsCtx(t), func(q *db.Queries) (err error) {
		rows, err = q.ListAuditLogs(t.Context(), &db.ListAuditLogsParams{
			Actions: []string{"ExchangeWorkloadToken"}, Limit: 1000,
		})
		return err
	}))
	return rows
}

// A job that matches a rule signs in with nothing stored, as a service account.
func TestExchangeSignsAJobIn(t *testing.T) {
	f := newFederation(t)
	_, enrolled := enrollTestDaemon(t, f.cfg, f.srv, testWorkspace.ID, true)
	targetID := enrolled.GetTargetId()
	admin := header("Authorization",
		"Bearer "+seedMember(t, f.cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN))
	grants := nokkuv1connect.NewTargetAccountServiceClient(
		clientOn(f.srv, admin),
	)
	root, err := grants.AddTargetAccount(t.Context(), &nokkuv1.AddTargetAccountRequest{
		TargetId: &targetID, Username: new("root"),
	})
	require.NoError(t, err)
	_, err = grants.AddSubjects(t.Context(), &nokkuv1.AddSubjectsRequest{
		Id:         root.GetAccount().Id,
		Kind:       nokkuv1.SubjectKind_SUBJECT_KIND_SERVICE_ACCOUNT.Enum(),
		SubjectIds: []string{f.account.GetId()},
	})
	require.NoError(t, err)

	res, session := f.signIn(t)
	assert.True(t, strings.HasPrefix(res.GetAccessToken(), "nk_sa_"), "the token is %q", res.GetAccessToken())
	got, err := f.whoami(t, signedIn(t, f.cfg, session))
	require.NoError(t, err)
	assert.Equal(t, f.account.GetId(), got)

	// It asks for two days, a person could get that.
	sshKey, err := gossh.NewPublicKey(f.key.Public())
	require.NoError(t, err)
	signed, err := nokkuv1connect.NewCertificateServiceClient(
		clientOn(f.srv, signedIn(t, f.cfg, session)),
	).SignSSHCertificate(t.Context(), &nokkuv1.SignSSHCertificateRequest{
		TargetId:  &targetID,
		PublicKey: new(string(gossh.MarshalAuthorizedKey(sshKey))),
		Ttl:       durationpb.New(48 * time.Hour),
	})
	require.NoError(t, err)
	assert.False(t, signed.GetExpiresAt().AsTime().After(res.GetExpiresAt().AsTime()),
		"the certificate outlives the session")
	key, _, _, _, err := gossh.ParseAuthorizedKey([]byte(signed.GetSignedCertificate()))
	require.NoError(t, err)
	cert, ok := key.(*gossh.Certificate)
	require.True(t, ok)
	assert.Equal(t, map[string]string{
		"force-command":  "/usr/local/bin/deploy",
		"source-address": "198.51.100.0/24",
	}, cert.CriticalOptions, "the limits of the account must reach the certificate")

	rows := f.exchangeRows(t)
	require.NotEmpty(t, rows)
	assert.True(t, rows[0].Ok)
	assert.Equal(t, f.account.GetName(), rows[0].ActorName)
	assert.Equal(t, f.account.GetId(), rows[0].ActorID)
	assert.Contains(t, string(rows[0].Details), jobSubject)
}

// A session lasts as long as the job token at most, and an hour at most.
func TestExchangeSessionLifetime(t *testing.T) {
	f := newFederation(t)
	claims := f.issuer.claims()
	exp := time.Now().Add(10 * time.Minute).Truncate(time.Second)
	claims["exp"] = exp.Unix()
	short, err := f.exchange(t, f.account.GetName(), f.issuer.sign(t, claims), f.proof(t))
	require.NoError(t, err)
	assert.WithinDuration(t, exp, short.GetExpiresAt().AsTime(), time.Second, "a session must end with its job token")
	assert.False(t, short.GetExpiresAt().AsTime().After(exp), "a session outlives its job token")

	claims = f.issuer.claims()
	claims["exp"] = time.Now().Add(6 * time.Hour).Unix()
	long, err := f.exchange(t, f.account.GetName(), f.issuer.sign(t, claims), f.proof(t))
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(time.Hour), long.GetExpiresAt().AsTime(), time.Minute,
		"a job token that lives long gives the hour and no more")
}

// A job token close to the age limit and an iat within the skew still sign in.
func TestExchangeTakesATokenWithinItsWindow(t *testing.T) {
	f := newFederation(t)
	for name, iat := range map[string]time.Time{
		"old, inside the window": time.Now().Add(-58 * time.Minute),
		"a little ahead":         time.Now().Add(30 * time.Second),
	} {
		claims := f.issuer.claims()
		claims["iat"] = iat.Unix()
		_, err := f.exchange(t, f.account.GetName(), f.issuer.sign(t, claims), f.proof(t))
		require.NoError(t, err, name)
	}
}

// Every refusal looks alike to a caller, only the audit row says why.
func TestExchangeRefusals(t *testing.T) {
	f := newFederation(t)
	cfg := f.cfg
	other := newJobIssuer(t)
	f.addRule(t, f.account, map[string]string{"sub": "numbers", "run_id": "42"})

	rogue := f.addAccount(t)
	f.addRule(t, rogue, map[string]string{"sub": "only-the-other-account"})
	empty := f.addAccount(t)

	otherWS := seedOtherWorkspace(t, cfg)
	foreign := uniq("foreign")
	inWorkspace(t, cfg, otherWS, func(q *db.Queries) error {
		id, err := q.CreateServiceAccount(t.Context(), &db.CreateServiceAccountParams{
			Name: foreign,
			Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
		})
		if err != nil {
			return err
		}
		_, err = q.CreateServiceAccountFederation(t.Context(), &db.CreateServiceAccountFederationParams{
			ServiceAccountID: id,
			Issuer:           f.issuer.url(),
			Claims:           map[string]string{"sub": jobSubject},
		})
		return err
	})

	claimed := func(change func(c map[string]any)) string {
		c := f.issuer.claims()
		change(c)
		return f.issuer.sign(t, c)
	}
	without := func(name string) string { return claimed(func(c map[string]any) { delete(c, name) }) }
	tampered := func() string {
		parts := strings.Split(f.issuer.sign(t, f.issuer.claims()), ".")
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, err)
		parts[1] = base64.RawURLEncoding.EncodeToString(
			[]byte(strings.ReplaceAll(string(payload), jobSubject, "repo:acme/app:ref:refs/heads/dev")),
		)
		return strings.Join(parts, ".")
	}()
	forged := func() string {
		// Another key, under the name of the issuer the rule trusts.
		c := other.claims()
		c["iss"] = f.issuer.url()
		return other.sign(t, c)
	}()
	unsigned := func() string {
		head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
		body, err := json.Marshal(f.issuer.claims())
		require.NoError(t, err)
		return head + "." + base64.RawURLEncoding.EncodeToString(body) + "."
	}()
	longJTI := strings.Repeat("x", 300)

	for _, tt := range []struct {
		name    string
		account string
		token   string
		reason  string // the audit row's reason, empty if no issuer vouched
	}{
		{"wrong audience", f.account.GetName(), claimed(func(c map[string]any) { c["aud"] = "https://elsewhere.test" }), "expected audience"},
		{"no audience", f.account.GetName(), without("aud"), "expected audience"},
		{"wrong issuer", f.account.GetName(), other.sign(t, other.claims()), ""},
		{"no issuer", f.account.GetName(), without("iss"), ""},
		{"tampered signature", f.account.GetName(), tampered, ""},
		{"another key under the issuer's name", f.account.GetName(), forged, ""},
		{"no signature", f.account.GetName(), unsigned, ""},
		{"not a token", f.account.GetName(), "garbage", ""},
		{"expired", f.account.GetName(), claimed(func(c map[string]any) {
			c["exp"] = time.Now().Add(-time.Minute).Unix()
		}), "expired"},
		{"no exp", f.account.GetName(), without("exp"), "expired"},
		{"iat too old", f.account.GetName(), claimed(func(c map[string]any) {
			c["iat"] = time.Now().Add(-2 * time.Hour).Unix()
		}), "too old"},
		// A session row lives an hour and an iat may run a minute ahead. Past
		// 59 minutes the row can be gone, and the job token replays.
		{"iat older than a session row covers", f.account.GetName(), claimed(func(c map[string]any) {
			c["iat"] = time.Now().Add(-59*time.Minute - 30*time.Second).Unix()
		}), "too old"},
		{"iat in the future", f.account.GetName(), claimed(func(c map[string]any) {
			c["iat"] = time.Now().Add(5 * time.Minute).Unix()
		}), "in the future"},
		{"no iat", f.account.GetName(), without("iat"), "no iat"},
		{"no jti", f.account.GetName(), without("jti"), "no usable jti"},
		{"a jti that is no string", f.account.GetName(), claimed(func(c map[string]any) { c["jti"] = 7 }), "no usable jti"},
		{"a jti too long", f.account.GetName(), claimed(func(c map[string]any) { c["jti"] = longJTI }), "no usable jti"},
		{"a claim that differs", f.account.GetName(), claimed(func(c map[string]any) { c["sub"] = "repo:acme/app:ref:refs/heads/dev" }), "no rule of the issuer matches"},
		{"a claim that is no string", f.account.GetName(), claimed(func(c map[string]any) { c["sub"] = "numbers" }), "no rule of the issuer matches"},
		{"a rule of another account", rogue.GetName(), f.issuer.sign(t, f.issuer.claims()), "no rule of the issuer matches"},
		{"an account with no rules", empty.GetName(), f.issuer.sign(t, f.issuer.claims()), ""},
		{"an unknown account", uniq("nobody"), f.issuer.sign(t, f.issuer.claims()), ""},
		{"an account of another workspace", foreign, f.issuer.sign(t, f.issuer.claims()), ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := len(f.exchangeRows(t))
			_, err := f.exchange(t, tt.account, tt.token, f.proof(t))
			assert.Equal(t, refusedAs, rpcAnswer(err))
			rows := f.exchangeRows(t)
			if tt.reason == "" {
				assert.Len(t, rows, before, "anyone can send this, it must not reach the log of the workspace")
				return
			}
			require.NotEmpty(t, rows)
			assert.False(t, rows[0].Ok, "a refused exchange is recorded as refused")
			assert.Contains(t, string(rows[0].Details), tt.reason, "the row must say why")
			assert.Contains(t, string(rows[0].Details), `"code": "unauthenticated"`, "the denied filter reads this")
		})
	}

	t.Run("no DPoP proof", func(t *testing.T) {
		token := f.issuer.sign(t, f.issuer.claims())
		_, err := f.exchange(t, f.account.GetName(), token)
		assert.Equal(t, refusedAs, rpcAnswer(err))
		_, err = f.exchange(t, f.account.GetName(), token, f.proof(t))
		require.NoError(t, err, "a call refused for its proof must not spend the job token")
	})
	t.Run("a bad DPoP proof", func(t *testing.T) {
		_, err := f.exchange(t, f.account.GetName(), f.issuer.sign(t, f.issuer.claims()),
			header("DPoP", "not-a-proof"))
		assert.Equal(t, refusedAs, rpcAnswer(err))
	})
}

// A stale nonce is no refusal, signing again does not cost the job token.
func TestExchangeStaleNonceKeepsTheJobToken(t *testing.T) {
	f := newFederation(t)
	token := f.issuer.sign(t, f.issuer.claims())
	before := len(f.exchangeRows(t))
	_, err := f.exchange(t, f.account.GetName(), token,
		header("DPoP", dpopProofWithNonce(t, f.key, exchange, "", "stale")))
	assert.Equal(t, "unauthenticated: stale DPoP nonce", rpcAnswer(err))
	assert.Len(t, f.exchangeRows(t), before, "signing again is no refused exchange")
	_, err = f.exchange(t, f.account.GetName(), token, f.proof(t))
	require.NoError(t, err)
}

// With nk's real client, whose first proof has no nonce, so that round runs.
func TestExchangeThroughTheClientOfNk(t *testing.T) {
	f := newFederation(t)
	proofer, err := dpop.NewProofer(f.key)
	require.NoError(t, err)
	session := "a session of some earlier run"
	signer := dpopclient.New(proofer, f.srv.Client(), func() string { return session }, dpopclient.Options{
		BaseURL:           testWorkspace.BaseURL,
		UnboundProcedures: map[string]bool{exchange: true},
	})
	rpc := clientOn(f.srv, signer.Intercept)
	before := len(f.exchangeRows(t))

	res, err := nokkuv1connect.NewAuthServiceClient(rpc).ExchangeWorkloadToken(t.Context(),
		&nokkuv1.ExchangeWorkloadTokenRequest{
			ServiceAccount: f.account.Name,
			Token:          new(f.issuer.sign(t, f.issuer.claims())),
		})
	require.NoError(t, err)
	session = res.GetAccessToken()

	rows := f.exchangeRows(t)
	require.Len(t, rows, before+1, "the nonce round left a row of its own")
	assert.True(t, rows[0].Ok)
	access, err := nokkuv1connect.NewTargetServiceClient(rpc).GetSubjectAccess(t.Context(),
		&nokkuv1.GetSubjectAccessRequest{})
	require.NoError(t, err)
	assert.Equal(t, f.account.GetId(), access.GetServiceAccount().GetId())
}

// A job token works once, whatever key asks and however its session ended.
func TestExchangeReplay(t *testing.T) {
	f := newFederation(t)
	token := f.issuer.sign(t, f.issuer.claims())
	first, err := f.exchange(t, f.account.GetName(), token, f.proof(t))
	require.NoError(t, err)

	_, err = f.exchange(t, f.account.GetName(), token, f.proof(t))
	assert.Equal(t, refusedAs, rpcAnswer(err))
	rows := f.exchangeRows(t)
	require.NotEmpty(t, rows)
	assert.Contains(t, string(rows[0].Details), "used before")
	_, err = f.exchange(t, f.account.GetName(), token, header("DPoP", dpopProof(t, f.cfg, dpopKey(t), exchange, "")))
	assert.Equal(t, refusedAs, rpcAnswer(err), "another key does not make it another job")

	// A revoke must not free the job token. It may still be good for an hour.
	list, err := f.accounts.ListServiceAccountTokens(t.Context(), &nokkuv1.ListServiceAccountTokensRequest{
		ServiceAccountId: f.account.Id,
	})
	require.NoError(t, err)
	require.Len(t, list.GetTokens(), 1)
	assert.Equal(t, jobSubject, list.GetTokens()[0].GetLabel())
	_, err = f.accounts.RevokeServiceAccountToken(t.Context(), &nokkuv1.RevokeServiceAccountTokenRequest{
		ServiceAccountId: f.account.Id,
		Id:               list.GetTokens()[0].Id,
	})
	require.NoError(t, err)
	_, err = f.whoami(t, signedIn(t, f.cfg, login{token: first.GetAccessToken(), key: f.key}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "a revoked session still signs in, %v", err)
	_, err = f.exchange(t, f.account.GetName(), token, f.proof(t))
	assert.Equal(t, refusedAs, rpcAnswer(err), "a revoke freed the job token")
	list, err = f.accounts.ListServiceAccountTokens(t.Context(), &nokkuv1.ListServiceAccountTokensRequest{
		ServiceAccountId: f.account.Id,
	})
	require.NoError(t, err)
	assert.Empty(t, list.GetTokens(), "a revoked session is still listed")
	_, err = f.accounts.RevokeServiceAccountToken(t.Context(), &nokkuv1.RevokeServiceAccountTokenRequest{
		ServiceAccountId: f.account.Id,
		Id:               new(uuid.NewV7().String()),
	})
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "got %v", err)
}

// The session is bound to the proof's key, a leaked token is useless alone.
func TestExchangeBindsTheSessionToItsKey(t *testing.T) {
	f := newFederation(t)
	_, session := f.signIn(t)

	_, err := f.whoami(t, signedIn(t, f.cfg, login{token: session.token, key: dpopKey(t)}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "another key got in, %v", err)
	_, err = f.whoami(t, header("Authorization", "Bearer "+session.token))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "no key got in, %v", err)

	got, err := f.whoami(t, signedIn(t, f.cfg, session))
	require.NoError(t, err)
	assert.Equal(t, f.account.GetId(), got)
}

func TestRemovedRuleStopsWorking(t *testing.T) {
	f := newFederation(t)
	f.signIn(t)

	listed, err := f.accounts.ListServiceAccountFederations(t.Context(), &nokkuv1.ListServiceAccountFederationsRequest{
		ServiceAccountId: f.account.Id,
	})
	require.NoError(t, err)
	require.Len(t, listed.GetFederations(), 1)
	assert.Equal(t, f.rule.GetId(), listed.GetFederations()[0].GetId())
	assert.Equal(t, map[string]string{"sub": jobSubject}, listed.GetFederations()[0].GetClaims())

	_, err = f.accounts.RemoveServiceAccountFederation(t.Context(), &nokkuv1.RemoveServiceAccountFederationRequest{
		ServiceAccountId: new(uuid.NewV7().String()),
		Id:               f.rule.Id,
	})
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "a rule removed through another account, %v", err)
	_, err = f.accounts.RemoveServiceAccountFederation(t.Context(), &nokkuv1.RemoveServiceAccountFederationRequest{
		ServiceAccountId: f.account.Id,
		Id:               f.rule.Id,
	})
	require.NoError(t, err)

	_, err = f.exchange(t, f.account.GetName(), f.issuer.sign(t, f.issuer.claims()), f.proof(t))
	assert.Equal(t, refusedAs, rpcAnswer(err), "a removed rule still signs in")
	_, err = f.accounts.RemoveServiceAccountFederation(t.Context(), &nokkuv1.RemoveServiceAccountFederationRequest{
		ServiceAccountId: f.account.Id,
		Id:               f.rule.Id,
	})
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "removing it twice, %v", err)
}

func TestRulesGoWithTheirAccount(t *testing.T) {
	f := newFederation(t)
	_, err := f.accounts.DeleteServiceAccount(t.Context(), &nokkuv1.DeleteServiceAccountRequest{Id: f.account.Id})
	require.NoError(t, err)
	listed, err := f.accounts.ListServiceAccountFederations(t.Context(), &nokkuv1.ListServiceAccountFederationsRequest{
		ServiceAccountId: f.account.Id,
	})
	require.NoError(t, err)
	assert.Empty(t, listed.GetFederations())
}

// A weak rule never gets stored, and the error tells the admin why.
func TestFederationRuleValidation(t *testing.T) {
	const (
		github = "https://token.actions.githubusercontent.com"
		gitlab = "https://gitlab.com"
		custom = "https://ci.example.test"
	)
	f := newFederation(t)
	for _, tt := range []struct {
		name   string
		issuer string
		claims map[string]string
		want   string // part of the refusal, empty when the rule is stored
	}{
		{"github with an environment", github, map[string]string{"repository_id": "74", "environment": "prod"}, ""},
		{"github with a ref", github, map[string]string{"repository_id": "74", "ref": "refs/heads/main"}, ""},
		{"github with extra claims", github, map[string]string{
			"repository_id": "74", "ref": "refs/heads/main", "workflow": "deploy",
		}, ""},
		{"gitlab with an environment", gitlab, map[string]string{"project_id": "9", "environment": "prod"}, ""},
		{"gitlab with a ref and its type", gitlab, map[string]string{
			"project_id": "9", "ref": "main", "ref_type": "branch",
		}, ""},
		{"gitlab with a ref path", gitlab, map[string]string{"project_id": "9", "ref_path": "refs/heads/main"}, ""},
		{"gitlab with a ref alone", gitlab, map[string]string{"project_id": "9", "ref": "main"}, "ref_type"},
		{"another issuer with sub", custom, map[string]string{"sub": "job"}, ""},
		{"an issuer with a path", custom + "/ci", map[string]string{"sub": "job"}, ""},

		{"plain http", "http://ci.example.test", map[string]string{"sub": "job"}, "https URL"},
		{"no scheme", "ci.example.test", map[string]string{"sub": "job"}, "https URL"},
		{"a query", custom + "?tenant=1", map[string]string{"sub": "job"}, "no query"},
		{"an empty query", custom + "?", map[string]string{"sub": "job"}, "no query"},
		{"a fragment", custom + "#a", map[string]string{"sub": "job"}, "https URL"},
		{"a user", "https://me@ci.example.test", map[string]string{"sub": "job"}, "https URL"},
		{"a space", custom + "/a b", map[string]string{"sub": "job"}, "https URL"},
		{"no issuer", "", map[string]string{"sub": "job"}, "https URL"},

		{"no claims", custom, nil, "at least one claim"},
		{"an empty value", custom, map[string]string{"sub": "job", "ref": ""}, "needs a value"},
		{"a blank value", custom, map[string]string{"sub": " "}, "needs a value"},
		{"an empty name", custom, map[string]string{"sub": "job", "": "x"}, "needs a name"},
		{"aud", custom, map[string]string{"sub": "job", "aud": "x"}, "can't be matched on"},
		{"iss", custom, map[string]string{"sub": "job", "iss": "x"}, "can't be matched on"},
		{"exp", custom, map[string]string{"sub": "job", "exp": "1"}, "can't be matched on"},
		{"iat", custom, map[string]string{"sub": "job", "iat": "1"}, "can't be matched on"},
		{"nbf", custom, map[string]string{"sub": "job", "nbf": "1"}, "can't be matched on"},
		{"jti", custom, map[string]string{"sub": "job", "jti": "x"}, "can't be matched on"},

		{"github with the repository alone", github, map[string]string{"repository_id": "74"}, "every branch and pull request"},
		{"github with a ref alone", github, map[string]string{"ref": "refs/heads/main"}, "repository_id"},
		{"github with sub alone", github, map[string]string{"sub": jobSubject}, "repository_id"},
		{"github with a repository name", github, map[string]string{"repository": "acme/app", "ref": "refs/heads/main"}, "registered again"},
		{"github spelled with a slash", github + "/", map[string]string{"sub": jobSubject}, "repository_id"},
		{"github in capitals", "https://TOKEN.actions.githubusercontent.com", map[string]string{"sub": jobSubject}, "repository_id"},
		{"github with a custom path", github + "/acme", map[string]string{"sub": jobSubject}, "repository_id"},
		{"gitlab with the project alone", gitlab, map[string]string{"project_id": "9"}, "every branch and merge request"},
		{"gitlab with sub alone", gitlab, map[string]string{"sub": "project_path:a/b:ref_type:branch:ref:main"}, "project_id"},
		{"another issuer without sub", custom, map[string]string{"repository_id": "74", "ref": "main"}, "needs sub"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			added, err := f.accounts.AddServiceAccountFederation(
				t.Context(),
				&nokkuv1.AddServiceAccountFederationRequest{
					ServiceAccountId: f.account.Id,
					Issuer:           &tt.issuer,
					Claims:           tt.claims,
				},
			)
			if tt.want == "" {
				require.NoError(t, err)
				assert.Equal(t, tt.claims, added.GetFederation().GetClaims())
				return
			}
			assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "got %v", err)
			require.ErrorContains(t, err, tt.want)
		})
	}
}

// A refused exchange logs workspace and account, never the job token.
func TestRefusedExchangeReachesTheAuditLog(t *testing.T) {
	f := newFederation(t)
	claims := f.issuer.claims()
	claims["sub"] = "repo:acme/app:ref:refs/heads/dev"
	token := f.issuer.sign(t, claims)
	_, err := f.exchange(t, f.account.GetName(), token, f.proof(t))
	require.Equal(t, refusedAs, rpcAnswer(err))

	rows := f.exchangeRows(t)
	require.NotEmpty(t, rows)
	row := rows[0]
	assert.False(t, row.Ok)
	assert.Equal(t, testWorkspace.ID, row.WorkspaceID)
	assert.Equal(t, f.account.GetName(), row.ActorName)
	assert.Equal(t, f.account.GetId(), row.ActorID)
	var details map[string]any
	require.NoError(t, json.Unmarshal(row.Details, &details))
	assert.Contains(t, details["reason"], "no rule of the issuer matches")

	parts := strings.Split(token, ".")
	stored := row.ActorName + row.Target + row.UserAgent + string(row.Details)
	for _, part := range parts {
		assert.NotContains(t, stored, part, "a piece of the job token reached the log")
	}
}

// A signing stop reaches the exchange, public calls skip the plan gates.
func TestExchangeFollowsThePlan(t *testing.T) {
	f := newFederation(t)
	local := *f.cfg
	var err error
	local.Entitlements, err = entitlement.New(t.Context(), f.cfg.Conn, "", true)
	require.NoError(t, err)
	stopped := httptest.NewServer(serving(api.New(&local).Handler(t.Context())))
	t.Cleanup(stopped.Close)

	// A hosted server reads no plan as inactive, a hosted trial is ended for it.
	restore := withoutAPlan(t, f.cfg)
	t.Cleanup(restore)

	inactive := federation{cfg: f.cfg, srv: stopped}
	token := f.issuer.sign(t, f.issuer.claims())
	_, err = inactive.exchange(t, f.account.GetName(), token, f.proof(t))
	assert.Equal(t, refusedAs, rpcAnswer(err))
	rows := f.exchangeRows(t)
	require.NotEmpty(t, rows)
	assert.Contains(t, string(rows[0].Details), "does not sign")

	restore()
	_, err = f.exchange(t, f.account.GetName(), token, f.proof(t))
	require.NoError(t, err, "a plan refusal must not spend the job token")
}

// nk logout ends a job's session on the core, the job token stays spent.
func TestLogoutEndsACISession(t *testing.T) {
	f := newFederation(t)
	token := f.issuer.sign(t, f.issuer.claims())
	res, err := f.exchange(t, f.account.GetName(), token, f.proof(t))
	require.NoError(t, err)
	session := signedIn(t, f.cfg, login{token: res.GetAccessToken(), key: f.key})
	_, err = f.whoami(t, session)
	require.NoError(t, err)

	_, err = nokkuv1connect.NewAuthServiceClient(
		clientOn(f.srv, session),
	).Logout(t.Context(), &nokkuv1.LogoutRequest{})
	require.NoError(t, err)

	_, err = f.whoami(t, session)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "the session outlived the logout: %v", err)
	_, err = f.exchange(t, f.account.GetName(), token, f.proof(t))
	assert.Equal(t, refusedAs, rpcAnswer(err), "a logout freed the job token")
}

// Rules per account are capped, every exchange that names it loads them all.
func TestRulesPerAccountAreCapped(t *testing.T) {
	f := newFederation(t)
	account := f.addAccount(t)
	add := func(i int) error {
		_, err := f.accounts.AddServiceAccountFederation(t.Context(), &nokkuv1.AddServiceAccountFederationRequest{
			ServiceAccountId: account.Id,
			Issuer:           new(f.issuer.url()),
			Claims:           map[string]string{"sub": "job-" + strconv.Itoa(i)},
		})
		return err
	}
	for i := range 32 {
		require.NoError(t, add(i))
	}
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(add(32)))
}

// No session goes out before the log has it, the exchange writes that row.
func TestExchangeNeedsItsAuditRow(t *testing.T) {
	f := newFederation(t)
	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	restore := func() {
		_, err := owner.Exec(context.WithoutCancel(t.Context()), "GRANT INSERT ON audit.audit_logs TO nokku_app")
		require.NoError(t, err)
	}
	t.Cleanup(func() { restore(); _ = owner.Close(context.WithoutCancel(t.Context())) })
	_, err = owner.Exec(t.Context(), "REVOKE INSERT ON audit.audit_logs FROM nokku_app")
	require.NoError(t, err)

	token := f.issuer.sign(t, f.issuer.claims())
	res, err := f.exchange(t, f.account.GetName(), token, f.proof(t))
	require.Error(t, err, "a session went out with no row in the log")
	assert.Empty(t, res.GetAccessToken())
	restore()

	_, err = f.exchange(t, f.account.GetName(), token, f.proof(t))
	assert.Equal(t, refusedAs, rpcAnswer(err), "the job token stays spent, whatever became of its session")
}

// A key without an end date is what a CI system forgets about.
func TestServiceAccountKeyNeedsAnEndDate(t *testing.T) {
	f := newFederation(t)
	_, err := f.accounts.CreateServiceAccountToken(t.Context(), &nokkuv1.CreateServiceAccountTokenRequest{
		ServiceAccountId: f.account.Id,
		Label:            new("forever"),
	})
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "got %v", err)
	require.ErrorContains(t, err, "end date")

	_, err = f.accounts.CreateServiceAccountToken(t.Context(), &nokkuv1.CreateServiceAccountTokenRequest{
		ServiceAccountId: f.account.Id,
		ExpiresAt:        timestamppb.New(time.Now().Add(time.Hour)),
	})
	require.NoError(t, err)
}
