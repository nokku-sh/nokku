package iam

// Store-backed tests run against the compose.test.yml Postgres and skip
// without it. Accounts are global, so every test works in fresh workspaces
// under random email domains and runs never collide.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/cache"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

const testBaseURL = "http://nokku.test"

type testEnv struct {
	svc  *Service
	conn *db.Connection
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	// The mock IdPs listen on loopback.
	t.Setenv("NOKKU_SSO_ALLOW_PRIVATE_NETWORKS", "true")
	cipher, err := crypto.NewSecretbox([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.SetEncryptor(cipher); err != nil {
		t.Fatal(err)
	}
	conn, err := db.NewConnection(t.Context())
	if err != nil {
		t.Skipf("no test database: %v", err)
	}
	svc, err := New(t.Context(), Deps{
		BaseURL:          testBaseURL,
		Conn:             conn,
		Cache:            cache.NewMemory(1000),
		Secret:           []byte("test-secret"),
		Password:         PasswordParams{Time: 1, Memory: 1024, Threads: 1, SaltLen: 16, KeyLen: 32},
		PasskeyRPOrigins: []string{testBaseURL},
	})
	if err != nil {
		t.Fatalf("build iam service: %v", err)
	}
	return &testEnv{svc: svc, conn: conn}
}

// testDomain returns an email domain no other test uses.
func testDomain() string {
	return strings.ReplaceAll(uuid.NewV7().String(), "-", "") + ".test"
}

// user creates an account, verified or not.
func (e *testEnv) user(t *testing.T, email string, verified bool) *db.User {
	t.Helper()
	ctx := t.Context()
	u, err := e.conn.Sys().CreateUser(ctx, &db.CreateUserParams{Email: email, Name: "Test"})
	if err != nil {
		t.Fatalf("create user %s: %v", email, err)
	}
	if verified {
		if err := e.conn.Sys().VerifyUserEmail(ctx, u.ID); err != nil {
			t.Fatal(err)
		}
		u.EmailVerified = true
	}
	return u
}

// workspace creates a workspace owned by owner.
func (e *testEnv) workspace(t *testing.T, owner string) string {
	t.Helper()
	ws, err := e.conn.Sys().
		CreateWorkspace(t.Context(), &db.CreateWorkspaceParams{Name: "ws-" + owner[:8], CreatedBy: owner})
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	return ws.ID
}

func (e *testEnv) member(t *testing.T, ws, userID string) {
	t.Helper()
	if err := e.conn.Sys().EnsureWorkspaceMember(t.Context(), &db.EnsureWorkspaceMemberParams{
		WorkspaceID: ws,
		UserID:      userID,
		RoleName:    "viewer",
	}); err != nil {
		t.Fatalf("add member: %v", err)
	}
}

// claimDomain verifies domain for ws, evicting any other claim.
func (e *testEnv) claimDomain(t *testing.T, ws, domain string) {
	t.Helper()
	err := e.conn.WithTx(t.Context(), func(q *db.Queries) error {
		d, err := q.UpsertWorkspaceDomain(t.Context(), &db.UpsertWorkspaceDomainParams{WorkspaceID: ws, Domain: domain})
		if err != nil {
			return err
		}
		_, err = q.VerifyWorkspaceDomain(
			t.Context(),
			&db.VerifyWorkspaceDomainParams{WorkspaceID: ws, Domain: domain, Token: d.Token},
		)
		return err
	})
	if err != nil {
		t.Fatalf("claim domain: %v", err)
	}
}

func (e *testEnv) dropDomain(t *testing.T, ws, domain string) {
	t.Helper()
	if err := e.conn.Sys().
		DeleteWorkspaceDomain(t.Context(), &db.DeleteWorkspaceDomainParams{WorkspaceID: ws, Domain: domain}); err != nil {
		t.Fatal(err)
	}
}

// org is an enterprise workspace: an owner under a verified domain.
type org struct {
	ws, domain string
	owner      *db.User
}

func (e *testEnv) org(t *testing.T) org {
	t.Helper()
	domain := testDomain()
	owner := e.user(t, "owner@"+domain, true)
	ws := e.workspace(t, owner.ID)
	e.claimDomain(t, ws, domain)
	return org{ws: ws, domain: domain, owner: owner}
}

// provider stores an enabled enterprise provider for o.
func (e *testEnv) provider(t *testing.T, o org, p SSOProvider) {
	t.Helper()
	p.WorkspaceID = o.ws
	p.ProviderID = o.ws
	p.Enabled = true
	if err := putSSOProvider(t.Context(), e.conn.Sys(), p); err != nil {
		t.Fatalf("store provider: %v", err)
	}
}

func (e *testEnv) userByEmail(t *testing.T, email string) *db.User {
	t.Helper()
	u, err := e.conn.Sys().GetUserByEmail(t.Context(), email)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (e *testEnv) credential(t *testing.T, typ Method, provider, subject string) *db.Credential {
	t.Helper()
	c, err := e.conn.Sys().FindCredentialBySubject(t.Context(), &db.FindCredentialBySubjectParams{
		Type:     string(typ),
		Provider: provider,
		Subject:  subject,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *testEnv) sessions(t *testing.T, subjectID string) int {
	t.Helper()
	rows, err := e.conn.Sys().ListSessionsBySubject(t.Context(), subjectID)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func (e *testEnv) isMember(t *testing.T, ws, userID string) bool {
	t.Helper()
	_, err := e.conn.Sys().
		UserWorkspaceMember(t.Context(), &db.UserWorkspaceMemberParams{WorkspaceID: ws, UserID: userID})
	return err == nil
}

// as returns a context signed in as the user.
func as(ctx context.Context, userID string) context.Context {
	return actor.ContextWithPrincipal(ctx, actor.Principal{ID: userID, Kind: actor.KindUser})
}
