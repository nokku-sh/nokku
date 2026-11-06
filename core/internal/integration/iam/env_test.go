//go:build integration

package iam_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/crypto/kms"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
	"github.com/nokku-sh/nokku/core/internal/tenant"
)

const (
	testBaseURL = "http://nokku.test"
	// What a browser holds and a mailed link carries.
	sessionCookieName = "nokku_session"
	loginVerifyURL    = "/login/verify?token="
	inviteURL         = "/invite?token="
	// An nk session must name the SSH key it signed in with.
	testSSHKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFnqlkEEgnnAYIr5pXed65L5FfJ5iwFb/dx4g0LI+YJe"
)

// accessTokens are all kinds, for a test that takes whichever it got.
var accessTokens = []crypto.TokenKind{
	crypto.TokenSession, crypto.TokenCLI, crypto.TokenDaemon, crypto.TokenServiceAccount, crypto.TokenSCIM,
}

type testEnv struct {
	svc  *iam.Service
	conn *db.Connection
	keys *kms.Keyset
}

// org is a workspace with its owner.
type org struct {
	ws    actor.Workspace
	owner *db.User
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	return newTestEnvWith(t, iam.Deps{})
}

// newTestEnvWith takes the mail and seat functions, fills in Conn and Keyset.
func newTestEnvWith(t *testing.T, deps iam.Deps) *testEnv {
	t.Helper()
	// The mock IdPs listen on loopback.
	t.Setenv("NOKKU_ALLOW_PRIVATE_NETWORKS", "true")
	conn, err := db.NewConnection(t.Context())
	require.NoError(t, err, "connect")
	t.Setenv("NOKKU_SECRET", "test-secret-0123456789-0123456789")
	keys, err := kms.New(t.Context(), conn, false)
	require.NoError(t, err, "open the keyset")
	deps.Conn, deps.Keyset = conn, keys
	svc, err := iam.New(t.Context(), deps)
	require.NoError(t, err, "build iam service")
	return &testEnv{svc: svc, conn: conn, keys: keys}
}

// normalizeEmail is the form the schema takes an address in.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// testDomain returns an email domain no other test uses.
func testDomain() string {
	return strings.ReplaceAll(uuid.NewV7().String(), "-", "") + ".test"
}

// workspace is a fresh tenant with its CA, served at testBaseURL.
func (e *testEnv) workspace(t *testing.T) actor.Workspace {
	t.Helper()
	slug := "w" + strings.ReplaceAll(uuid.NewV7().String(), "-", "")[:12]
	ws, err := tenant.Create(t.Context(), e.conn, e.keys, slug, "Test")
	require.NoError(t, err, "create workspace")
	return actor.Workspace{ID: ws.ID, Slug: ws.Slug, BaseURL: testBaseURL}
}

// in runs fn the way a request does: nokku_app, pinned to ws.
func (e *testEnv) in(t *testing.T, ws actor.Workspace, fn func(q *db.Queries) error) error {
	t.Helper()
	return e.conn.TenantTx(anon(t.Context(), ws), fn)
}

func (e *testEnv) org(t *testing.T) org {
	t.Helper()
	ws := e.workspace(t)
	return org{ws: ws, owner: e.user(t, ws, "owner@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER)}
}

func (e *testEnv) user(t *testing.T, ws actor.Workspace, email string, role nokkuv1.WorkspaceRole) *db.User {
	t.Helper()
	var u *db.User
	require.NoError(t, e.in(t, ws, func(q *db.Queries) (err error) {
		u, err = q.CreateUser(t.Context(), &db.CreateUserParams{
			Email: normalizeEmail(email), Name: "Test", Role: role,
		})
		return err
	}), "create user %s", email)
	return u
}

func (e *testEnv) provider(t *testing.T, ws actor.Workspace, p iam.SSOProvider) {
	t.Helper()
	p.Enabled = true
	_, err := e.svc.PutSSOProvider(anon(t.Context(), ws), p)
	require.NoError(t, err, "store provider")
}

func (e *testEnv) putCredential(t *testing.T, ws actor.Workspace, p db.UpsertCredentialParams) {
	t.Helper()
	require.NoError(t, e.in(t, ws, func(q *db.Queries) error {
		_, err := q.UpsertCredential(t.Context(), &p)
		return err
	}), "store credential %s", p.ID)
}

func (e *testEnv) setEnforceSSO(t *testing.T, ws actor.Workspace, on bool) {
	t.Helper()
	require.NoError(t, e.in(t, ws, func(q *db.Queries) error {
		w, err := q.GetWorkspace(t.Context())
		if err != nil {
			return err
		}
		w.Settings.EnforceSso = new(on)
		_, err = q.UpdateWorkspace(t.Context(), &db.UpdateWorkspaceParams{Settings: w.Settings})
		return err
	}))
}

func (e *testEnv) userByEmail(t *testing.T, ws actor.Workspace, email string) *db.User {
	t.Helper()
	var u *db.User
	err := e.in(t, ws, func(q *db.Queries) (err error) {
		u, err = q.GetUserByEmail(t.Context(), normalizeEmail(email))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	require.NoError(t, err)
	return u
}

func (e *testEnv) oidcCredential(
	t *testing.T,
	ws actor.Workspace,
	provider, subject string,
) *db.Credential {
	t.Helper()
	var c *db.Credential
	err := e.in(t, ws, func(q *db.Queries) (err error) {
		c, err = q.FindCredentialBySubject(t.Context(), &db.FindCredentialBySubjectParams{
			Type:     string(iam.MethodOIDC),
			Provider: provider,
			Subject:  subject,
		})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	require.NoError(t, err)
	return c
}

func (e *testEnv) sessions(t *testing.T, ws actor.Workspace, subjectID string) int {
	t.Helper()
	var rows []*db.AccessToken
	require.NoError(t, e.in(t, ws, func(q *db.Queries) (err error) {
		rows, err = q.ListUserSessions(t.Context(), subjectID)
		return err
	}))
	return len(rows)
}

func (e *testEnv) passkeys(t *testing.T, ws actor.Workspace, userID string) int {
	t.Helper()
	var rows []*db.Credential
	require.NoError(t, e.in(t, ws, func(q *db.Queries) (err error) {
		rows, err = q.ListCredentialsByType(t.Context(), &db.ListCredentialsByTypeParams{
			UserID: userID, Type: string(iam.MethodPasskey),
		})
		return err
	}))
	return len(rows)
}

// anon is a request on the workspace's host with nobody signed in.
func anon(ctx context.Context, ws actor.Workspace) context.Context {
	return actor.WithWorkspace(ctx, ws)
}

// as is a request on the workspace's host from a browser u just signed in on.
func as(ctx context.Context, ws actor.Workspace, u *db.User) context.Context {
	ctx = iam.ContextWithToken(ctx, db.AccessToken{Kind: string(actor.KindUser), CreatedAt: time.Now()})
	return actor.ContextWithPrincipal(anon(ctx, ws), actor.Principal{ID: u.ID, Kind: actor.KindUser, Role: u.Role})
}

// linkToken is the token a mailed link carries.
func linkToken(t *testing.T, link string) string {
	t.Helper()
	_, token, ok := strings.Cut(link, "token=")
	require.True(t, ok, "link %q carries no token", link)
	require.NotEmpty(t, token, "link %q carries no token", link)
	return token
}
