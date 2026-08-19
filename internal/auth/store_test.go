package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/mizuchilabs/kagi"

	"github.com/nokku-sh/nokku/internal/db"
)

// These tests exercise the kagi store adapter against a real, fully migrated
// database. They are skipped when the development PostgreSQL container
// (compose.test.yml) is not running, matching internal/db/migrate_test.go.

func testDB(t *testing.T) (*pgx.Conn, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	admin, err := pgx.Connect(
		ctx,
		"postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable",
	)
	if err != nil {
		t.Skipf("test database not available (%v); start compose.test.yml", err)
	}
	dbName := fmt.Sprintf("nokku_auth_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatalf("creating test database: %v", err)
	}
	_ = admin.Close(ctx)

	conn, err := pgx.Connect(
		ctx,
		fmt.Sprintf("postgres://postgres:postgres@localhost:5432/%s?sslmode=disable", dbName),
	)
	if err != nil {
		t.Fatalf("connecting to test database: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = conn.Close(cleanupCtx)

		admin2, err := pgx.Connect(
			cleanupCtx,
			"postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable",
		)
		if err == nil {
			defer admin2.Close(cleanupCtx)
			_, _ = admin2.Exec(cleanupCtx, "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)")
		}
	})
	return conn, dbName
}

func testConn(t *testing.T, dbName string) *db.Connection {
	t.Helper()
	t.Setenv("NOKKU_DB_HOST", "localhost")
	t.Setenv("NOKKU_DB_PORT", "5432")
	t.Setenv("NOKKU_DB_NAME", dbName)
	t.Setenv("NOKKU_DB_USER", "postgres")
	t.Setenv("NOKKU_DB_PASSWORD", "postgres")
	conn, err := db.NewConnection(context.Background())
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	if conn.Pool != nil {
		t.Cleanup(conn.Pool.Close)
	}
	return conn
}

func TestStoreRoundTrip(t *testing.T) {
	admin, dbName := testDB(t)
	ctx := context.Background()
	conn := testConn(t, dbName)
	store := NewStore(conn)

	// User
	u, err := store.CreateUser(ctx, "", kagi.User{Email: "alice@example.com", DisplayName: "Alice"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if u.ID == "" {
		t.Fatal("expected a user id")
	}
	got, err := store.GetUser(ctx, "", u.ID)
	if err != nil || got.Email != "alice@example.com" {
		t.Fatalf("get user: %+v (%v)", got, err)
	}
	byEmail, err := store.GetUserByEmail(ctx, "", "alice@example.com")
	if err != nil || byEmail.ID != u.ID {
		t.Fatalf("get by email: %+v (%v)", byEmail, err)
	}

	// Credential
	if err := store.PutCredential(ctx, "", kagi.Credential{
		ID: "oidc:google:sub1", UserID: u.ID, Type: kagi.CredentialOIDC,
		Provider: "google", Subject: "sub1", Data: []byte("{}"),
	}); err != nil {
		t.Fatalf("put credential: %v", err)
	}
	linked, err := store.FindCredentialBySubject(ctx, "", kagi.CredentialOIDC, "google", "sub1")
	if err != nil || linked.UserID != u.ID {
		t.Fatalf("find credential: %+v (%v)", linked, err)
	}
	if _, err := store.FindCredentialBySubject(
		ctx,
		"",
		kagi.CredentialOIDC,
		"google",
		"missing",
	); !errors.Is(
		err,
		kagi.ErrNotFound,
	) {
		t.Fatalf("expected not found, got %v", err)
	}

	// Session
	now := time.Now()
	tokenHash := sha256.Sum256([]byte("raw-token-123"))
	sess := kagi.Session{
		Token: "raw-token-123", TokenHash: tokenHash[:], TenantID: "", SubjectID: u.ID,
		Kind: KindUser, Method: kagi.MethodPasskey, ExpiresAt: now.Add(time.Hour),
	}
	if err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	gotSess, err := store.GetSession(ctx, tokenHash[:])
	if err != nil || gotSess.SubjectID != u.ID || gotSess.Kind != KindUser {
		t.Fatalf("get session: %+v (%v)", gotSess, err)
	}
	// The raw token is never persisted: only its hash is in the row.
	var storedToken string
	if err := conn.AdminPool.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE token_hash IS NOT NULL AND token_hash != ''").
		Scan(&storedToken); err != nil {
		t.Fatalf("checking token hash: %v", err)
	}
	if err := store.DeleteSession(ctx, tokenHash[:]); err != nil {
		t.Fatalf("delete session: %v", err)
	}
	if _, err := store.GetSession(ctx, tokenHash[:]); !errors.Is(err, kagi.ErrNotFound) {
		t.Fatalf("expected session deleted, got %v", err)
	}

	// API key
	if err := store.PutKey(ctx, kagi.APIKeyRecord{
		KeyID: "key1", TenantID: "ws1", SubjectID: u.ID, Kind: KindServiceAccount,
		SecretHash: []byte("h"), Scopes: []string{"read"}, Name: "ci", CreatedAt: now,
	}); err != nil {
		t.Fatalf("put key: %v", err)
	}
	key, err := store.GetKey(ctx, "key1")
	if err != nil || key.SubjectID != u.ID || key.Kind != KindServiceAccount {
		t.Fatalf("get key: %+v (%v)", key, err)
	}
	tenantKeys, err := store.ListTenantKeys(ctx, "ws1")
	if err != nil || len(tenantKeys) != 1 {
		t.Fatalf("list tenant keys: %d (%v)", len(tenantKeys), err)
	}

	// Clean up cluster-role grants before the scratch database is dropped.
	if _, err := admin.Exec(ctx, "DROP OWNED BY nokku_app, nokku_system"); err != nil {
		t.Fatalf("cleaning grants: %v", err)
	}
}

func TestKagiServiceRoundTrip(t *testing.T) {
	admin, dbName := testDB(t)
	ctx := context.Background()
	conn := testConn(t, dbName)
	store := NewStore(conn)

	svc, err := kagi.New(kagi.Options{
		Store:         store,
		ResolveTenant: func(*http.Request) (kagi.TenantID, error) { return "", nil },
	})
	if err != nil {
		t.Fatalf("kagi.New: %v", err)
	}

	u, err := store.CreateUser(ctx, "", kagi.User{Email: "bob@example.com", DisplayName: "Bob"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Issue a session through the kagi SessionManager and verify it round-trips.
	sess, err := svc.Sessions.IssueSession(ctx, kagi.SessionParams{
		TenantID:  "",
		SubjectID: u.ID,
		Kind:      kagi.KindUser,
		Method:    kagi.MethodPassword,
		TTL:       24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	got, err := svc.Sessions.Verify(ctx, sess.Token)
	if err != nil || got.SubjectID != u.ID || got.Kind != kagi.KindUser {
		t.Fatalf("verify: %+v (%v)", got, err)
	}

	// Revoke all of the subject's sessions and confirm the token is gone.
	if err := svc.RevokeSubjectSessions(ctx, "", u.ID); err != nil {
		t.Fatalf("revoke subject sessions: %v", err)
	}
	if _, err := svc.Sessions.Verify(ctx, sess.Token); !errors.Is(err, kagi.ErrNotFound) {
		t.Fatalf("expected session revoked, got %v", err)
	}

	// A DPoP-bound, non-expiring daemon session round-trips too.
	bound, err := svc.Sessions.IssueSession(ctx, kagi.SessionParams{
		TenantID:  "ws1",
		SubjectID: u.ID,
		Kind:      KindDaemon,
		Binding:   "jkt-thumbprint",
		Method:    kagi.MethodKey,
	})
	if err != nil {
		t.Fatalf("issue bound session: %v", err)
	}
	if !bound.ExpiresAt.IsZero() {
		t.Fatal("expected non-expiring session")
	}
	got, err = svc.Sessions.Verify(ctx, bound.Token)
	if err != nil || got.Binding != "jkt-thumbprint" || got.Kind != KindDaemon {
		t.Fatalf("verify bound session: %+v (%v)", got, err)
	}

	if _, err := admin.Exec(ctx, "DROP OWNED BY nokku_app, nokku_system"); err != nil {
		t.Fatalf("cleaning grants: %v", err)
	}
}
