package db

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/crypto"
)

// stateFixture is one workspace where user u reaches principal p on a daemon
// target twice: directly and through team.
type stateFixture struct {
	ws, owner, u, team, daemon, target, principal string
}

func newStateFixture(t *testing.T, c *Connection) stateFixture {
	t.Helper()
	f := stateFixture{
		ws:        uuid.NewV7().String(),
		owner:     uuid.NewV7().String(),
		u:         uuid.NewV7().String(),
		team:      uuid.NewV7().String(),
		daemon:    uuid.NewV7().String(),
		target:    uuid.NewV7().String(),
		principal: uuid.NewV7().String(),
	}
	// The simple protocol substitutes arguments client-side, which allows
	// several statements in one Exec.
	_, err := c.sysPool.Exec(t.Context(), `
		INSERT INTO users (id, email) VALUES ($2, $2 || '@test'), ($3, $3 || '@test');
		INSERT INTO workspaces (id, name, created_by) VALUES ($1, 'ws', $2);
		INSERT INTO workspace_members (workspace_id, user_id, role_name)
		VALUES ($1, $2, 'owner'), ($1, $3, 'viewer');
		INSERT INTO teams (id, workspace_id, name) VALUES ($4, $1, 'team');
		INSERT INTO team_members (workspace_id, user_id, team_id) VALUES ($1, $3, $4);
		INSERT INTO daemons (id, workspace_id, name, status) VALUES ($5, $1, 'd', 2);
		INSERT INTO targets (id, workspace_id, daemon_id, name) VALUES ($6, $1, $5, 't');
		INSERT INTO principals (id, workspace_id, target_id, username) VALUES ($7, $1, $6, 'deploy');
		INSERT INTO principal_grants (principal_id, workspace_id, user_id) VALUES ($7, $1, $3);
		INSERT INTO principal_grants (principal_id, workspace_id, team_id) VALUES ($7, $1, $4);
	`, pgx.QueryExecModeSimpleProtocol, f.ws, f.owner, f.u, f.team, f.daemon, f.target, f.principal)
	if err != nil {
		t.Fatalf("seed fixture: %v", err)
	}
	return f
}

func testConnection(t *testing.T) *Connection {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	c, err := NewConnection(t.Context())
	if err != nil {
		t.Skipf("no test database: %v", err)
	}
	if err := c.sysPool.Ping(ctx); err != nil {
		t.Skipf("no test database: %v", err)
	}
	return c
}

func stateVersion(t *testing.T, c *Connection, ws string) int64 {
	t.Helper()
	v, err := c.Sys().GetWorkspaceStateVersion(t.Context(), ws)
	if err != nil {
		t.Fatalf("read state version: %v", err)
	}
	return v
}

func grantedIDs(t *testing.T, c *Connection, target string) []string {
	t.Helper()
	rows, err := c.Sys().ListPrincipalsForTarget(t.Context(), target)
	if err != nil {
		t.Fatalf("list principals: %v", err)
	}
	if len(rows) == 0 {
		return nil
	}
	return rows[0].Ids
}

// asOwner runs fn the way API handlers do: nokku_app, pinned to the workspace.
func asOwner(t *testing.T, c *Connection, f stateFixture, fn func(*Queries) error) {
	t.Helper()
	ctx := actor.ContextWithPrincipal(t.Context(), actor.Principal{ID: f.owner, Kind: actor.KindUser})
	ctx = actor.AnnotateTenant(ctx, f.ws)
	if err := c.WithWorkspace(ctx, fn); err != nil {
		t.Fatalf("workspace tx: %v", err)
	}
}

func listen(t *testing.T, c *Connection) *pgx.Conn {
	t.Helper()
	conn, err := pgx.ConnectConfig(t.Context(), c.Pool.Config().ConnConfig)
	if err != nil {
		t.Fatalf("listen connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	if _, err := conn.Exec(t.Context(), "LISTEN nokku_state"); err != nil {
		t.Fatalf("listen: %v", err)
	}
	return conn
}

func waitNotify(t *testing.T, conn *pgx.Conn, ws string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			t.Fatalf("no state notification for %s: %v", ws, err)
		}
		if n.Payload == ws {
			return
		}
	}
}

func TestStateVersionBumpsOnAccessChanges(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	conn := listen(t, c)

	if got := grantedIDs(t, c, f.target); len(got) != 1 || got[0] != f.u {
		t.Fatalf("granted ids = %v, want [%s]", got, f.u)
	}

	before := stateVersion(t, c, f.ws)
	asOwner(t, c, f, func(q *Queries) error {
		return q.RemoveTeamMember(t.Context(), &RemoveTeamMemberParams{TeamID: f.team, UserID: f.u})
	})
	waitNotify(t, conn, f.ws)
	if after := stateVersion(t, c, f.ws); after <= before {
		t.Fatalf("team member removal: version %d -> %d, want a bump", before, after)
	}

	before = stateVersion(t, c, f.ws)
	asOwner(t, c, f, func(q *Queries) error {
		return q.RemoveWorkspaceMember(t.Context(), &RemoveWorkspaceMemberParams{WorkspaceID: f.ws, UserID: f.u})
	})
	waitNotify(t, conn, f.ws)
	if after := stateVersion(t, c, f.ws); after <= before {
		t.Fatalf("member removal: version %d -> %d, want a bump", before, after)
	}
	if got := grantedIDs(t, c, f.target); len(got) != 0 {
		t.Fatalf("removed member still granted: %v", got)
	}
}

// A deactivated account must leave every daemon's map at once, a cert it
// already holds would otherwise work until it expires.
func TestDeactivatedUserLosesAccess(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	conn := listen(t, c)

	setActive := func(active bool) {
		if _, err := c.Sys().UpdateUser(t.Context(), &UpdateUserParams{ID: f.u, Active: &active}); err != nil {
			t.Fatalf("set active=%v: %v", active, err)
		}
	}

	before := stateVersion(t, c, f.ws)
	setActive(false)
	waitNotify(t, conn, f.ws)
	if after := stateVersion(t, c, f.ws); after <= before {
		t.Fatalf("deactivation: version %d -> %d, want a bump", before, after)
	}
	if got := grantedIDs(t, c, f.target); len(got) != 0 {
		t.Fatalf("deactivated user still granted: %v", got)
	}

	setActive(true)
	waitNotify(t, conn, f.ws)
	if got := grantedIDs(t, c, f.target); len(got) != 1 || got[0] != f.u {
		t.Fatalf("reactivated user: granted ids = %v, want [%s]", got, f.u)
	}
}

func TestStateVersionIgnoresHeartbeatWrites(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)

	before := stateVersion(t, c, f.ws)
	asOwner(t, c, f, func(q *Queries) error {
		if err := q.UpdateDaemonMetadata(t.Context(), &UpdateDaemonMetadataParams{
			DaemonID: f.daemon,
			Metadata: []byte(`{"host":"x"}`),
		}); err != nil {
			return err
		}
		if _, err := q.UpdateTarget(t.Context(), &UpdateTargetParams{
			TargetID:  f.target,
			Metadata:  []byte(`{"os":"linux"}`),
			Endpoints: []string{"10.0.0.1:4022"},
		}); err != nil {
			return err
		}
		return q.InsertTargetPrincipals(t.Context(), &InsertTargetPrincipalsParams{
			TargetID:  f.target,
			Usernames: []string{"deploy", "backup"},
		})
	})
	if after := stateVersion(t, c, f.ws); after != before {
		t.Fatalf("heartbeat writes moved the version %d -> %d", before, after)
	}
}

func TestGrantRejectsForeignTeam(t *testing.T) {
	c := testConnection(t)
	a := newStateFixture(t, c)
	b := newStateFixture(t, c)

	_, err := c.sysPool.Exec(t.Context(),
		`INSERT INTO principal_grants (principal_id, workspace_id, team_id) VALUES ($1, $2, $3)`,
		a.principal, a.ws, b.team)
	if err == nil {
		t.Fatal("granted a team from another workspace")
	}
}

// Parallel redemptions of a one-use token spend it exactly once.
func TestRedeemTokenOnce(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	id := uuid.NewV7().String()
	hash := crypto.HashedToken("h-" + id)
	if _, err := c.Sys().CreateWorkspaceToken(t.Context(), &CreateWorkspaceTokenParams{
		ID:          id,
		WorkspaceID: f.ws,
		Kind:        nokkuv1.TokenKind_TOKEN_KIND_INVITE,
		TokenHash:   hash,
		MaxUses:     new(int32(1)),
		RoleName:    new("viewer"),
	}); err != nil {
		t.Fatalf("create token: %v", err)
	}

	const n = 8
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			_, err := c.Sys().RedeemToken(t.Context(), &RedeemTokenParams{
				ID: id, Kind: nokkuv1.TokenKind_TOKEN_KIND_INVITE, TokenHash: hash,
			})
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, pgx.ErrNoRows) {
				t.Errorf("redeem: %v", err)
			}
		})
	}
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("%d redemptions succeeded, want 1", got)
	}
}
