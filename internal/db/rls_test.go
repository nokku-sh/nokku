package db

import (
	"context"
	"errors"
	"testing"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/actor"
)

// seedIdentity gives user a credential and a session, and returns an outsider
// who shares no workspace with anyone in f.
func seedIdentity(t *testing.T, c *Connection, f stateFixture) string {
	t.Helper()
	outsider := uuid.NewV7().String()
	_, err := c.sysPool.Exec(t.Context(), `
		INSERT INTO users (id, email) VALUES ($3, $3 || '@test');
		INSERT INTO credentials (id, user_id, type, data) VALUES ($1 || '-pw', $1, 'password', 'x');
		INSERT INTO credentials (id, user_id, type, data) VALUES ($2 || '-pw', $2, 'password', 'x');
		INSERT INTO sessions (token_hash, subject_id, user_id, method) VALUES ($1 || '-s', $1, $1, 'password');
		INSERT INTO sessions (token_hash, subject_id, user_id, method) VALUES ($2 || '-s', $2, $2, 'password');
	`, pgx.QueryExecModeSimpleProtocol, f.owner, f.u, outsider)
	if err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	return outsider
}

func asActor(t *testing.T, c *Connection, id string, fn func(*Queries) error) {
	t.Helper()
	if err := c.WithActor(t.Context(), id, fn); err != nil {
		t.Fatalf("actor tx: %v", err)
	}
}

func TestActorSeesOnlyOwnIdentity(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	seedIdentity(t, c, f)

	asActor(t, c, f.owner, func(q *Queries) error {
		if _, err := q.GetUser(t.Context(), f.owner); err != nil {
			t.Errorf("own user not visible: %v", err)
		}
		if _, err := q.GetUser(t.Context(), f.u); !errors.Is(err, pgx.ErrNoRows) {
			t.Errorf("other user visible without a pinned workspace: %v", err)
		}
		creds, err := q.ListCredentialsByType(t.Context(), &ListCredentialsByTypeParams{UserID: f.u, Type: "password"})
		if err != nil || len(creds) != 0 {
			t.Errorf("read another user's credentials: %d rows, err %v", len(creds), err)
		}
		sessions, err := q.ListSessionsBySubject(t.Context(), f.u)
		if err != nil || len(sessions) != 0 {
			t.Errorf("read another user's sessions: %d rows, err %v", len(sessions), err)
		}
		own, err := q.ListSessionsBySubject(t.Context(), f.owner)
		if err != nil || len(own) != 1 {
			t.Errorf("own sessions: %d rows, err %v", len(own), err)
		}
		name := "hijacked"
		if _, err := q.UpdateUser(
			t.Context(),
			&UpdateUserParams{ID: f.u, Name: &name},
		); !errors.Is(
			err,
			pgx.ErrNoRows,
		) {
			t.Errorf("updated another user: %v", err)
		}
		return nil
	})
}

func TestWorkspaceSeesOnlyMembers(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	outsider := seedIdentity(t, c, f)

	asOwner(t, c, f, func(q *Queries) error {
		if _, err := q.GetUser(t.Context(), f.u); err != nil {
			t.Errorf("fellow member not visible: %v", err)
		}
		if _, err := q.GetUser(t.Context(), outsider); !errors.Is(err, pgx.ErrNoRows) {
			t.Errorf("outsider visible from the workspace: %v", err)
		}
		creds, err := q.ListCredentialsByType(t.Context(), &ListCredentialsByTypeParams{UserID: f.u, Type: "password"})
		if err != nil || len(creds) != 0 {
			t.Errorf("read a member's credentials: %d rows, err %v", len(creds), err)
		}
		return nil
	})
}

// The fast path trusts the interceptor's membership check, and still pins
// the workspace so RLS applies.
func TestWithWorkspaceVerifiedMember(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	other := newStateFixture(t, c)

	ctx := actor.ContextWithPrincipal(t.Context(), actor.Principal{ID: f.owner, Kind: actor.KindUser})
	ctx = actor.AnnotateTenant(ctx, f.ws)
	ctx = actor.WithMember(ctx, f.ws, "")
	err := c.WithWorkspace(ctx, func(q *Queries) error {
		if _, err := q.GetTarget(t.Context(), f.target); err != nil {
			t.Errorf("own target not visible: %v", err)
		}
		if _, err := q.GetTarget(t.Context(), other.target); !errors.Is(err, pgx.ErrNoRows) {
			t.Errorf("foreign target visible: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("workspace tx: %v", err)
	}
}

func TestAppRoleCannotWriteAudit(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)

	ctx := actor.ContextWithPrincipal(t.Context(), actor.Principal{ID: f.owner, Kind: actor.KindUser})
	ctx = actor.AnnotateTenant(ctx, f.ws)
	err := c.WithWorkspace(ctx, func(q *Queries) error {
		return q.InsertAuditLog(t.Context(), &InsertAuditLogParams{
			WorkspaceID: &f.ws,
			Action:      "forged",
			ActorKind:   "user",
			Details:     []byte("{}"),
		})
	})
	if err == nil {
		t.Fatal("app role wrote an audit row")
	}
}

func TestAuditLogScopes(t *testing.T) {
	c := testConnection(t)
	a, b := newStateFixture(t, c), newStateFixture(t, c)
	for _, row := range []struct{ ws *string }{{&a.ws}, {&b.ws}, {nil}} {
		if err := c.Sys().InsertAuditLog(t.Context(), &InsertAuditLogParams{
			WorkspaceID: row.ws, ActorID: a.u, Action: "Test", Ok: true, Details: []byte("{}"),
		}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	if err := c.Sys().InsertAuditLog(t.Context(), &InsertAuditLogParams{
		WorkspaceID: &b.ws, ActorID: b.owner, Action: "Test", Ok: true, Details: []byte("{}"),
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	list := func(ctx context.Context, run func(context.Context, func(*Queries) error) error, ws *string) int {
		t.Helper()
		var rows []*ListAuditLogsRow
		if err := run(ctx, func(q *Queries) (err error) {
			rows, err = q.ListAuditLogs(ctx, &ListAuditLogsParams{WorkspaceID: ws, Limit: 100})
			return err
		}); err != nil {
			t.Fatalf("list: %v", err)
		}
		return len(rows)
	}

	personal := func(ctx context.Context, fn func(*Queries) error) error { return c.WithActor(ctx, a.u, fn) }
	if n := list(t.Context(), personal, nil); n != 3 {
		t.Errorf("personal log has %d rows, want the actor's 3 across workspaces", n)
	}

	ctx := actor.ContextWithPrincipal(t.Context(), actor.Principal{ID: a.owner, Kind: actor.KindUser})
	ctx = actor.AnnotateTenant(ctx, a.ws)
	if n := list(ctx, c.WithWorkspace, &a.ws); n != 1 {
		t.Errorf("workspace log has %d rows, want 1", n)
	}
	if n := list(ctx, c.WithWorkspace, &b.ws); n != 0 {
		t.Errorf("workspace a reads %d rows of workspace b, want 0", n)
	}

	if _, err := c.sysPool.Exec(t.Context(), "DELETE FROM workspaces WHERE id = $1", a.ws); err != nil {
		t.Fatalf("delete workspace with audit rows: %v", err)
	}
}
