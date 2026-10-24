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
)

type testEnv struct {
	svc  *iam.Service
	conn *db.Connection
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	return newTestEnvWith(t, iam.Deps{})
}

// newTestEnvWith takes the mail functions and the seat cap. Conn and Secret are filled in.
func newTestEnvWith(t *testing.T, deps iam.Deps) *testEnv {
	t.Helper()
	// The mock IdPs listen on loopback.
	t.Setenv("NOKKU_ALLOW_PRIVATE_NETWORKS", "true")
	conn, err := db.NewConnection(t.Context())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	cipher, err := kms.New(t.Context(), conn, "test-secret-0123456789-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.SetEncryptor(cipher); err != nil {
		t.Fatal(err)
	}
	deps.Conn, deps.Secret = conn, []byte("test-secret")
	svc, err := iam.New(t.Context(), deps)
	if err != nil {
		t.Fatalf("build iam service: %v", err)
	}
	return &testEnv{svc: svc, conn: conn}
}

// normalizeEmail is the form the schema takes an address in.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// testDomain returns an email domain no other test uses.
func testDomain() string {
	return strings.ReplaceAll(uuid.NewV7().String(), "-", "") + ".test"
}

// workspace is a fresh tenant with its default CA, served at testBaseURL.
func (e *testEnv) workspace(t *testing.T) actor.Workspace {
	t.Helper()
	slug := "w" + strings.ReplaceAll(uuid.NewV7().String(), "-", "")[:12]
	ws, err := tenant.Create(t.Context(), e.conn, slug, "Test")
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	return actor.Workspace{ID: ws.ID, Slug: ws.Slug, BaseURL: testBaseURL}
}

// in runs fn the way a request does: nokku_app, pinned to ws.
func (e *testEnv) in(t *testing.T, ws actor.Workspace, fn func(q *db.Queries) error) error {
	t.Helper()
	return e.conn.TenantTx(anon(t.Context(), ws), fn)
}

// org is a workspace with its owner.
type org struct {
	ws    actor.Workspace
	owner *db.User
}

func (e *testEnv) org(t *testing.T) org {
	t.Helper()
	ws := e.workspace(t)
	return org{ws: ws, owner: e.user(t, ws, "owner@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER)}
}

func (e *testEnv) user(t *testing.T, ws actor.Workspace, email string, role nokkuv1.WorkspaceRole) *db.User {
	t.Helper()
	var u *db.User
	err := e.in(t, ws, func(q *db.Queries) (err error) {
		u, err = q.CreateUser(t.Context(), &db.CreateUserParams{
			Email: normalizeEmail(email), Name: "Test", Role: role,
		})
		return err
	})
	if err != nil {
		t.Fatalf("create user %s: %v", email, err)
	}
	return u
}

// invite makes an invite link for ws. maxUses zero is unlimited.
func (e *testEnv) invite(t *testing.T, ws actor.Workspace, role nokkuv1.WorkspaceRole, maxUses int32) string {
	t.Helper()
	id := uuid.NewV7().String()
	tok := crypto.NewToken(id)
	params := &db.CreateJoinTokenParams{
		ID:        id,
		Kind:      nokkuv1.JoinTokenKind_JOIN_TOKEN_KIND_INVITE,
		TokenHash: tok.Hash,
		Role:      &role,
	}
	if maxUses > 0 {
		params.MaxUses = &maxUses
	}
	if err := e.in(t, ws, func(q *db.Queries) error {
		_, err := q.CreateJoinToken(t.Context(), params)
		return err
	}); err != nil {
		t.Fatalf("create invite: %v", err)
	}
	return tok.Plaintext
}

func (e *testEnv) provider(t *testing.T, ws actor.Workspace, p iam.SSOProvider) {
	t.Helper()
	p.Enabled = true
	if _, err := e.svc.PutSSOProvider(anon(t.Context(), ws), p); err != nil {
		t.Fatalf("store provider: %v", err)
	}
}

func (e *testEnv) putCredential(t *testing.T, ws actor.Workspace, p db.UpsertCredentialParams) {
	t.Helper()
	if err := e.in(t, ws, func(q *db.Queries) error {
		_, err := q.UpsertCredential(t.Context(), &p)
		return err
	}); err != nil {
		t.Fatalf("store credential %s: %v", p.ID, err)
	}
}

func (e *testEnv) setEnforceSSO(t *testing.T, ws actor.Workspace, on bool) {
	t.Helper()
	if err := e.in(t, ws, func(q *db.Queries) error {
		w, err := q.GetWorkspace(t.Context())
		if err != nil {
			return err
		}
		w.Settings.EnforceSso = new(on)
		_, err = q.UpdateWorkspace(t.Context(), &db.UpdateWorkspaceParams{Settings: w.Settings})
		return err
	}); err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *testEnv) sessions(t *testing.T, ws actor.Workspace, subjectID string) int {
	t.Helper()
	var rows []*db.AccessToken
	if err := e.in(t, ws, func(q *db.Queries) (err error) {
		rows, err = q.ListUserSessions(t.Context(), subjectID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func (e *testEnv) passkeys(t *testing.T, ws actor.Workspace, userID string) int {
	t.Helper()
	var rows []*db.Credential
	if err := e.in(t, ws, func(q *db.Queries) (err error) {
		rows, err = q.ListCredentialsByType(t.Context(), &db.ListCredentialsByTypeParams{
			UserID: userID, Type: string(iam.MethodPasskey),
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

// anon is a request on the workspace's host with nobody signed in.
func anon(ctx context.Context, ws actor.Workspace) context.Context {
	return actor.WithWorkspace(ctx, ws)
}

// as is a request on the workspace's host from a browser that signed in as u a moment ago.
func as(ctx context.Context, ws actor.Workspace, u *db.User) context.Context {
	ctx = iam.ContextWithToken(ctx, db.AccessToken{Kind: string(actor.KindUser), CreatedAt: time.Now()})
	return actor.ContextWithPrincipal(anon(ctx, ws), actor.Principal{ID: u.ID, Kind: actor.KindUser, Role: u.Role})
}

// linkToken is the token a mailed link carries.
func linkToken(t *testing.T, link string) string {
	t.Helper()
	_, token, ok := strings.Cut(link, "token=")
	if !ok || token == "" {
		t.Fatalf("link %q carries no token", link)
	}
	return token
}
