package iam

import (
	"context"
	"errors"
	"strings"
	"testing"
	"uuid"

	"github.com/jackc/pgx/v5"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/crypto/kms"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/tenant"
)

const testBaseURL = "http://nokku.test"

type testEnv struct {
	svc  *Service
	conn *db.Connection
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	// The mock IdPs listen on loopback.
	t.Setenv("NOKKU_ALLOW_PRIVATE_NETWORKS", "true")
	conn, err := db.NewConnection(t.Context())
	if err != nil {
		t.Skipf("no test database: %v", err)
	}
	cipher, err := kms.New(t.Context(), conn, "test-secret-0123456789-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.SetEncryptor(cipher); err != nil {
		t.Fatal(err)
	}
	svc, err := New(t.Context(), Deps{Conn: conn, Secret: []byte("test-secret")})
	if err != nil {
		t.Fatalf("build iam service: %v", err)
	}
	return &testEnv{svc: svc, conn: conn}
}

// testDomain returns an email domain no other test uses.
func testDomain() string {
	return strings.ReplaceAll(uuid.NewV7().String(), "-", "") + ".test"
}

// workspace is a fresh tenant with its default CA, served at testBaseURL.
func (e *testEnv) workspace(t *testing.T) actor.Workspace {
	t.Helper()
	slug := "w" + strings.ReplaceAll(uuid.NewV7().String(), "-", "")[:12]
	var ws *db.Workspace
	err := e.conn.WithTx(t.Context(), func(q *db.Queries) (err error) {
		ws, err = tenant.Create(t.Context(), q, slug, "Test")
		return err
	})
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	return actor.Workspace{ID: ws.ID, Slug: ws.Slug, Name: ws.Name, BaseURL: testBaseURL}
}

// org is a workspace with its owner.
type org struct {
	ws    actor.Workspace
	owner *db.User
}

func (e *testEnv) org(t *testing.T) org {
	t.Helper()
	ws := e.workspace(t)
	return org{ws: ws, owner: e.user(t, ws, "owner@"+testDomain(), "owner")}
}

func (e *testEnv) user(t *testing.T, ws actor.Workspace, email, role string) *db.User {
	t.Helper()
	u, err := e.conn.Sys().CreateUser(t.Context(), &db.CreateUserParams{
		WorkspaceID: ws.ID, Email: normalizeEmail(email), Name: "Test", Role: role,
	})
	if err != nil {
		t.Fatalf("create user %s: %v", email, err)
	}
	return u
}

// invite makes an invite link for ws. maxUses zero is unlimited.
func (e *testEnv) invite(t *testing.T, ws actor.Workspace, role string, maxUses int32) string {
	t.Helper()
	id := uuid.NewV7().String()
	tok, err := crypto.NewToken(crypto.WithID(id))
	if err != nil {
		t.Fatal(err)
	}
	params := &db.CreateWorkspaceTokenParams{
		ID:          id,
		WorkspaceID: ws.ID,
		Kind:        nokkuv1.TokenKind_TOKEN_KIND_INVITE,
		TokenHash:   tok.Hash,
		RoleName:    &role,
	}
	if maxUses > 0 {
		params.MaxUses = &maxUses
	}
	if _, err := e.conn.Sys().CreateWorkspaceToken(t.Context(), params); err != nil {
		t.Fatalf("create invite: %v", err)
	}
	return tok.Plaintext
}

// provider stores an enabled provider for ws.
func (e *testEnv) provider(t *testing.T, ws actor.Workspace, p SSOProvider) {
	t.Helper()
	p.Enabled = true
	if _, err := putSSOProvider(t.Context(), e.conn.Sys(), ws.ID, p); err != nil {
		t.Fatalf("store provider: %v", err)
	}
}

func (e *testEnv) setEnforceSSO(t *testing.T, ws actor.Workspace, on bool) {
	t.Helper()
	w, err := e.conn.Sys().GetWorkspace(t.Context(), ws.ID)
	if err != nil {
		t.Fatal(err)
	}
	w.Settings.EnforceSso = new(on)
	if _, err := e.conn.Sys().UpdateWorkspace(t.Context(), &db.UpdateWorkspaceParams{
		WorkspaceID: ws.ID, Settings: w.Settings,
	}); err != nil {
		t.Fatal(err)
	}
}

func (e *testEnv) userByEmail(t *testing.T, ws actor.Workspace, email string) *db.User {
	t.Helper()
	u, err := e.conn.Sys().GetUserByEmail(t.Context(), &db.GetUserByEmailParams{
		WorkspaceID: ws.ID, Email: normalizeEmail(email),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (e *testEnv) credential(t *testing.T, ws actor.Workspace, typ Method, provider, subject string) *db.Credential {
	t.Helper()
	c, err := e.conn.Sys().FindCredentialBySubject(t.Context(), &db.FindCredentialBySubjectParams{
		WorkspaceID: ws.ID,
		Type:        string(typ),
		Provider:    provider,
		Subject:     subject,
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
	rows, err := e.conn.Sys().ListSessionsBySubject(t.Context(), &db.ListSessionsBySubjectParams{
		WorkspaceID: ws.ID, SubjectID: subjectID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func (e *testEnv) passkeys(t *testing.T, ws actor.Workspace, userID string) int {
	t.Helper()
	rows, err := e.conn.Sys().ListCredentialsByType(t.Context(), &db.ListCredentialsByTypeParams{
		WorkspaceID: ws.ID, UserID: userID, Type: string(MethodPasskey),
	})
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

// anon is a request on the workspace's host with nobody signed in.
func anon(ctx context.Context, ws actor.Workspace) context.Context {
	return actor.WithWorkspace(ctx, ws)
}

// as is a request on the workspace's host signed in as u.
func as(ctx context.Context, ws actor.Workspace, u *db.User) context.Context {
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
