//go:build integration

package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/core/internal/access"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// soleGrant leaves u with its direct grant only, ending at end. nil is for good.
func soleGrant(t *testing.T, c *conn, f stateFixture, end *time.Time) {
	t.Helper()
	_, err := c.sysPool.Exec(t.Context(), `
		DELETE FROM team_members WHERE user_id = $1;
		UPDATE grants SET expires_at = $2 WHERE account_id = $3 AND subject_id = $1;
	`, pgx.QueryExecModeSimpleProtocol, f.u, end, f.account)
	if err != nil {
		t.Fatalf("set the grant: %v", err)
	}
}

func usernames(t *testing.T, c *conn, f stateFixture) []*db.ListSubjectUsernamesForTargetsRow {
	t.Helper()
	rows, err := c.Sys().ListSubjectUsernamesForTargets(t.Context(), &db.ListSubjectUsernamesForTargetsParams{
		TargetIds: []string{f.target},
		SubjectID: f.u,
	})
	if err != nil {
		t.Fatalf("list usernames: %v", err)
	}
	return rows
}

func grantEnd(t *testing.T, c *conn, f stateFixture) (*time.Time, bool) {
	t.Helper()
	var end *time.Time
	err := c.sysPool.QueryRow(t.Context(),
		`SELECT expires_at FROM grants WHERE account_id = $1 AND subject_id = $2`, f.account, f.u,
	).Scan(&end)
	if err != nil {
		return nil, false
	}
	return end, true
}

// A grant past its end must not sign and must not be on a host, even before the job deletes it.
func TestEndedGrantResolvesNowhere(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	soleGrant(t, c, f, new(time.Now().Add(-time.Second)))

	if got := usernames(t, c, f); len(got) != 0 {
		t.Fatalf("an ended grant still signs: %v", got)
	}
	if got := grantedIDs(t, c, f.target); len(got) != 0 {
		t.Fatalf("an ended grant is still on the host: %v", got)
	}
}

func TestGrantEndIsTheLatestThatApplies(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	end := time.Now().Add(time.Hour).Truncate(time.Microsecond)
	soleGrant(t, c, f, &end)

	rows := usernames(t, c, f)
	if len(rows) != 1 || rows[0].Until() == nil || !rows[0].Until().Equal(end) {
		t.Fatalf("one grant ending at %v: got %+v", end, rows)
	}

	// Back in the team, whose grant is for good, the access is for good.
	if _, err := c.sysPool.Exec(t.Context(),
		`INSERT INTO team_members (workspace_id, user_id, team_id) VALUES ($1, $2, $3)`, f.ws, f.u, f.team,
	); err != nil {
		t.Fatalf("rejoin the team: %v", err)
	}
	rows = usernames(t, c, f)
	if len(rows) != 1 || rows[0].Until() != nil {
		t.Fatalf("a grant for good through the team: got until %v", rows[0].Until())
	}
}

func TestExpireDeletesBumpsAndAudits(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	soleGrant(t, c, f, new(time.Now().Add(-time.Second)))
	conn := listen(t, c)
	before := stateVersion(t, c, f.ws)

	// The database is shared, other tests leave ended grants in their workspaces.
	var events []*audit.Event
	write := func(_ context.Context, e *audit.Event) error {
		if e.WorkspaceID == f.ws {
			events = append(events, e)
		}
		return nil
	}
	if err := access.Expire(t.Context(), c.Connection, write); err != nil {
		t.Fatalf("expire: %v", err)
	}

	waitNotify(t, conn, f.ws)
	if after := stateVersion(t, c, f.ws); after <= before {
		t.Fatalf("expiry: version %d -> %d, want a bump so hosts drop the grant", before, after)
	}
	if _, ok := grantEnd(t, c, f); ok {
		t.Fatal("the ended grant is still there")
	}
	if len(events) != 1 || events[0].Action != "GrantExpired" || events[0].Details["subject_id"] != f.u {
		t.Fatalf("want one GrantExpired event for %s, got %+v", f.u, events)
	}

	// The team grant of the fixture is for good and stays.
	var left int
	if err := c.sysPool.QueryRow(t.Context(),
		`SELECT count(*) FROM grants WHERE account_id = $1`, f.account,
	).Scan(&left); err != nil || left != 1 {
		t.Fatalf("grants left = %d (%v), want the team grant", left, err)
	}
}

// An approval never shortens a grant or ends one for good. An admin's grant sets the end as asked.
func TestGrantWritesKeepOrSetTheEnd(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	soon := time.Now().Add(time.Hour).Truncate(time.Microsecond)
	later := soon.Add(time.Hour)
	ctx := t.Context()

	soleGrant(t, c, f, &soon)
	asOwner(t, c, f, func(q *db.Queries) error {
		return q.ExtendGrant(ctx, &db.ExtendGrantParams{AccountID: f.account, UserID: f.u, ExpiresAt: later})
	})
	if end, _ := grantEnd(t, c, f); end == nil || !end.Equal(later) {
		t.Fatalf("an approval for longer: end %v, want %v", end, later)
	}
	asOwner(t, c, f, func(q *db.Queries) error {
		return q.ExtendGrant(ctx, &db.ExtendGrantParams{AccountID: f.account, UserID: f.u, ExpiresAt: soon})
	})
	if end, _ := grantEnd(t, c, f); end == nil || !end.Equal(later) {
		t.Fatalf("an approval for less shortened the grant to %v", end)
	}

	asOwner(t, c, f, func(q *db.Queries) error {
		return q.PutGrant(ctx, &db.PutGrantParams{
			AccountID: f.account, SubjectKind: db.SubjectKindUser, SubjectID: f.u, ExpiresAt: &soon,
		})
	})
	if end, _ := grantEnd(t, c, f); end == nil || !end.Equal(soon) {
		t.Fatalf("an admin's shorter end: got %v, want %v", end, soon)
	}

	asOwner(t, c, f, func(q *db.Queries) error {
		return q.PutGrant(
			ctx,
			&db.PutGrantParams{AccountID: f.account, SubjectKind: db.SubjectKindUser, SubjectID: f.u},
		)
	})
	if end, _ := grantEnd(t, c, f); end != nil {
		t.Fatalf("an admin's grant for good still ends at %v", end)
	}
	asOwner(t, c, f, func(q *db.Queries) error {
		return q.ExtendGrant(ctx, &db.ExtendGrantParams{AccountID: f.account, UserID: f.u, ExpiresAt: soon})
	})
	if end, _ := grantEnd(t, c, f); end != nil {
		t.Fatalf("an approval made a grant for good end at %v", end)
	}
}
