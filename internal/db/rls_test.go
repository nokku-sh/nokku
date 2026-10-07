package db

import (
	"context"
	"errors"
	"testing"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/actor"
)

// seedIdentity gives the fixture's user a passkey and a session.
func seedIdentity(t *testing.T, c *Connection, f stateFixture) {
	t.Helper()
	_, err := c.sysPool.Exec(t.Context(), `
		INSERT INTO credentials (id, workspace_id, user_id, type, data) VALUES ($2 || '-pk', $1, $2, 'passkey', 'x');
		INSERT INTO sessions (token_hash, workspace_id, subject_id, user_id, kind, method)
		VALUES ($2 || '-s', $1, $2, $2, 'user', 'passkey');
	`, pgx.QueryExecModeSimpleProtocol, f.ws, f.u)
	if err != nil {
		t.Fatalf("seed identity: %v", err)
	}
}

func pinned(t *testing.T, ws string) context.Context {
	t.Helper()
	return actor.WithWorkspace(t.Context(), actor.Workspace{ID: ws})
}

func TestWorkspaceSeesOnlyItsOwnRows(t *testing.T) {
	c := testConnection(t)
	a, b := newStateFixture(t, c), newStateFixture(t, c)
	seedIdentity(t, c, a)
	seedIdentity(t, c, b)

	err := c.WithWorkspace(pinned(t, a.ws), func(q *Queries) error {
		if _, err := q.GetUser(t.Context(), &GetUserParams{WorkspaceID: a.ws, ID: a.u}); err != nil {
			t.Errorf("own user not visible: %v", err)
		}
		if _, err := q.GetUser(
			t.Context(),
			&GetUserParams{WorkspaceID: b.ws, ID: b.u},
		); !errors.Is(
			err,
			pgx.ErrNoRows,
		) {
			t.Errorf("foreign user visible: %v", err)
		}
		own, err := q.ListSessionsBySubject(
			t.Context(),
			&ListSessionsBySubjectParams{WorkspaceID: a.ws, SubjectID: a.u},
		)
		if err != nil || len(own) != 1 {
			t.Errorf("own sessions: %d rows, err %v", len(own), err)
		}
		foreign, err := q.ListSessionsBySubject(
			t.Context(),
			&ListSessionsBySubjectParams{WorkspaceID: b.ws, SubjectID: b.u},
		)
		if err != nil || len(foreign) != 0 {
			t.Errorf("read a foreign session: %d rows, err %v", len(foreign), err)
		}
		creds, err := q.ListCredentialsByType(t.Context(), &ListCredentialsByTypeParams{
			WorkspaceID: b.ws, UserID: b.u, Type: "passkey",
		})
		if err != nil || len(creds) != 0 {
			t.Errorf("read a foreign credential: %d rows, err %v", len(creds), err)
		}
		if _, err := q.GetTarget(t.Context(), b.target); !errors.Is(err, pgx.ErrNoRows) {
			t.Errorf("foreign target visible: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("workspace tx: %v", err)
	}

	// A write that names another workspace is refused by the policy.
	err = c.WithWorkspace(pinned(t, a.ws), func(q *Queries) error {
		_, err := q.CreateUser(t.Context(), &CreateUserParams{
			WorkspaceID: b.ws, Email: uuid.NewV7().String() + "@test", Role: "member",
		})
		return err
	})
	if err == nil {
		t.Error("wrote a user into another workspace")
	}
}

func TestUnpinnedRequestFailsClosed(t *testing.T) {
	c := testConnection(t)
	err := c.WithWorkspace(t.Context(), func(*Queries) error { return nil })
	if !errors.Is(err, ErrWorkspaceNotPinned) {
		t.Fatalf("err = %v, want ErrWorkspaceNotPinned", err)
	}
}

func TestAppRoleCannotWriteAudit(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)

	err := c.WithWorkspace(pinned(t, f.ws), func(q *Queries) error {
		return q.InsertAuditLog(t.Context(), &InsertAuditLogParams{
			WorkspaceID: f.ws,
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
	for _, row := range []struct{ ws, actor string }{{a.ws, a.u}, {b.ws, b.u}, {b.ws, b.owner}} {
		if err := c.Sys().InsertAuditLog(t.Context(), &InsertAuditLogParams{
			WorkspaceID: row.ws, ActorID: row.actor, Action: "Test", Ok: true, Details: []byte("{}"),
		}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	list := func(ws string) int {
		t.Helper()
		var rows []*ListAuditLogsRow
		if err := c.WithWorkspace(pinned(t, ws), func(q *Queries) (err error) {
			rows, err = q.ListAuditLogs(t.Context(), &ListAuditLogsParams{WorkspaceID: ws, Limit: 100})
			return err
		}); err != nil {
			t.Fatalf("list: %v", err)
		}
		return len(rows)
	}
	if n := list(a.ws); n != 1 {
		t.Errorf("workspace a has %d rows, want 1", n)
	}
	if n := list(b.ws); n != 2 {
		t.Errorf("workspace b has %d rows, want 2", n)
	}

	if _, err := c.sysPool.Exec(t.Context(), "DELETE FROM workspaces WHERE id = $1", a.ws); err != nil {
		t.Fatalf("delete workspace with audit rows: %v", err)
	}
}
