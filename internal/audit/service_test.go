package audit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/mizuchilabs/kagi"

	"github.com/nokku-sh/nokku/internal/auth"
	"github.com/nokku-sh/nokku/internal/billing"
	"github.com/nokku-sh/nokku/internal/db"
)

type stubLicense struct{}

func (stubLicense) Valid() bool { return false }

// testService creates a fresh, fully migrated database with the audit schema
// on top. Skipped when the development PostgreSQL container (compose.test.yml)
// is not running.
func testService(t *testing.T) (*Service, *db.Connection) {
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

	dbName := fmt.Sprintf("nokku_audit_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatalf("creating test database: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = admin.Exec(cleanupCtx, "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)")
		_ = admin.Close(cleanupCtx)
	})

	t.Setenv("NOKKU_DB_HOST", "localhost")
	t.Setenv("NOKKU_DB_PORT", "5432")
	t.Setenv("NOKKU_DB_NAME", dbName)
	t.Setenv("NOKKU_DB_USER", "postgres")
	t.Setenv("NOKKU_DB_PASSWORD", "postgres")

	conn, err := db.NewConnection(ctx)
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}

	svc, err := New(ctx, conn, billing.NewService(conn, stubLicense{}, nil, billing.ModeSelfHosted))
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	return svc, conn
}

// TestAuditSchemaRLS covers the externally managed audit policy: tenant logs
// are only readable from the pinned workspace, appends always work, and
// global (non-workspace) events are invisible to tenant roles.
func TestAuditSchemaRLS(t *testing.T) {
	svc, conn := testService(t)
	ctx := context.Background()

	var enabled, forced bool
	if err := conn.AdminPool.QueryRow(ctx, `
		SELECT c.relrowsecurity, c.relforcerowsecurity
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'audit' AND c.relname = 'audit_logs'`).Scan(&enabled, &forced); err != nil {
		t.Fatalf("checking audit RLS: %v", err)
	}
	if !enabled || !forced {
		t.Fatalf("audit.audit_logs: rls=%v force=%v, want both", enabled, forced)
	}

	owner, err := func() (*db.User, error) {
		var u *db.User
		err := conn.WithTx(ctx, func(q *db.Queries) (err error) {
			u, err = q.CreateUser(ctx, &db.CreateUserParams{
				Name: "Auditor", Username: "auditor", Email: "auditor@example.com",
			})
			return err
		})
		return u, err
	}()
	if err != nil {
		t.Fatalf("creating user: %v", err)
	}

	var ws *db.CreateWorkspaceRow
	if err := conn.WithTx(ctx, func(q *db.Queries) (err error) {
		ws, err = q.CreateWorkspace(ctx, &db.CreateWorkspaceParams{
			Name: "Audit WS", CreatedBy: owner.ID,
		})
		return err
	}); err != nil {
		t.Fatalf("creating workspace: %v", err)
	}

	if err := svc.Append(ctx, &Event{
		WorkspaceID: ws.ID, Action: "targets.create", ActorID: owner.ID, ActorType: "user",
	}); err != nil {
		t.Fatalf("append workspace event: %v", err)
	}
	if err := svc.Append(ctx, &Event{
		Action: "auth.login", ActorID: owner.ID, ActorType: "user",
	}); err != nil {
		t.Fatalf("append global event: %v", err)
	}

	// Pinned workspace read: sees the workspace event, but not the global one.
	actx := kagi.WithPrincipal(ctx, kagi.Principal{SubjectID: owner.ID, Kind: auth.ActorTypeUser})
	actx = kagi.WithTenant(actx, kagi.TenantID(ws.ID))

	events, err := svc.List(actx, QueryOptions{WorkspaceID: ws.ID})
	if err != nil {
		t.Fatalf("list workspace events: %v", err)
	}
	if len(events) != 1 || events[0].Action != "targets.create" {
		t.Fatalf("expected exactly the workspace event, got %+v", events)
	}

	// Unpinned workspace-scoped read must see nothing (fail closed). The
	// owner needs a second workspace for this, since WithWorkspace implicitly
	// pins single-workspace actors.
	if err := conn.WithTx(ctx, func(q *db.Queries) (err error) {
		_, err = q.CreateWorkspace(ctx, &db.CreateWorkspaceParams{
			Name: "Second WS", CreatedBy: owner.ID,
		})
		return err
	}); err != nil {
		t.Fatalf("creating second workspace: %v", err)
	}
	if err := conn.WithWorkspace(kagi.WithPrincipal(
		ctx, kagi.Principal{SubjectID: owner.ID, Kind: auth.ActorTypeUser},
	), func(q *db.Queries) error {
		rows, err := q.ListAuditLogs(ctx, &db.ListAuditLogsParams{WorkspaceID: ws.ID, Limit: 10})
		if err != nil {
			return err
		}
		if len(rows) != 0 {
			return fmt.Errorf("unpinned audit read leaked %d rows", len(rows))
		}
		return nil
	}); err != nil {
		t.Fatalf("unpinned audit read: %v", err)
	}
}
