//go:build integration

package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/access"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// soleGrant leaves u only its direct grant, ending at end. nil is for good.
func soleGrant(t *testing.T, c *conn, f stateFixture, end *time.Time) {
	t.Helper()
	_, err := c.sysPool.Exec(t.Context(), `
		DELETE FROM team_members WHERE user_id = $1;
		UPDATE grants SET expires_at = $2 WHERE account_id = $3 AND subject_id = $1;
	`, pgx.QueryExecModeSimpleProtocol, f.u, end, f.account)
	require.NoError(t, err, "set the grant")
}

func usernames(t *testing.T, c *conn, f stateFixture) []*db.ListSubjectUsernamesForTargetsRow {
	t.Helper()
	rows, err := c.Sys().ListSubjectUsernamesForTargets(t.Context(), &db.ListSubjectUsernamesForTargetsParams{
		TargetIds: []string{f.target},
		SubjectID: f.u,
	})
	require.NoError(t, err, "list usernames")
	return rows
}

func grantEnd(t *testing.T, c *conn, f stateFixture) (*time.Time, bool) {
	t.Helper()
	var end *time.Time
	err := c.sysPool.QueryRow(t.Context(),
		`SELECT expires_at FROM grants WHERE account_id = $1 AND subject_id = $2`, f.account, f.u,
	).Scan(&end)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false
	}
	require.NoError(t, err, "read the grant")
	return end, true
}

// A grant past its end signs nothing and is on no host, before the job runs
// too.
func TestEndedGrantResolvesNowhere(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	soleGrant(t, c, f, new(time.Now().Add(-time.Second)))

	require.Empty(t, usernames(t, c, f), "an ended grant still signs")
	require.Empty(t, grantedIDs(t, c, f.target), "an ended grant is still on the host")
}

func TestGrantEndIsTheLatestThatApplies(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	end := time.Now().Add(time.Hour).Truncate(time.Microsecond)
	soleGrant(t, c, f, &end)

	rows := usernames(t, c, f)
	require.Len(t, rows, 1, "one grant")
	require.NotNil(t, rows[0].Until(), "one grant ending at %v", end)
	require.WithinDuration(t, end, *rows[0].Until(), 0)

	// Back in the team, whose grant is for good, the access is for good.
	_, err := c.sysPool.Exec(t.Context(),
		`INSERT INTO team_members (workspace_id, user_id, team_id) VALUES ($1, $2, $3)`, f.ws, f.u, f.team,
	)
	require.NoError(t, err, "rejoin the team")
	rows = usernames(t, c, f)
	require.Len(t, rows, 1, "a grant for good through the team")
	require.Nil(t, rows[0].Until(), "a grant for good through the team")
}

func TestExpireDeletesNotifiesAndAudits(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	soleGrant(t, c, f, new(time.Now().Add(-time.Second)))
	w := watch(t, c, f.ws)

	// The database is shared, other tests leave their ended grants in it.
	var events []*audit.Event
	write := func(_ context.Context, e *audit.Event) error {
		if e.WorkspaceID == f.ws {
			events = append(events, e)
		}
		return nil
	}
	require.NoError(t, access.Expire(t.Context(), c.Connection, write), "expire")

	require.Equal(t, 1, w.seen(t), "nobody was told, hosts keep the grant")
	_, ok := grantEnd(t, c, f)
	require.False(t, ok, "the ended grant is still there")
	require.Len(t, events, 1, "want one GrantExpired event")
	require.Equal(t, "GrantExpired", events[0].Action)
	require.Equal(t, f.u, events[0].Details["subject_id"])

	// The team grant of the fixture is for good and stays.
	var left int
	require.NoError(t, c.sysPool.QueryRow(t.Context(),
		`SELECT count(*) FROM grants WHERE account_id = $1`, f.account,
	).Scan(&left))
	require.Equal(t, 1, left, "want the team grant")
}

// An approval never shortens a grant or ends one for good. An admin's grant
// sets the end as asked.
func TestGrantWritesKeepOrSetTheEnd(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	soon := time.Now().Add(time.Hour).Truncate(time.Microsecond)
	later := soon.Add(time.Hour)
	ctx := t.Context()
	wantEnd := func(want time.Time, msg string) {
		t.Helper()
		end, _ := grantEnd(t, c, f)
		require.NotNil(t, end, msg)
		require.WithinDuration(t, want, *end, 0, msg)
	}

	soleGrant(t, c, f, &soon)
	asOwner(t, c, f, func(q *db.Queries) error {
		return q.ExtendGrant(ctx, &db.ExtendGrantParams{AccountID: f.account, UserID: f.u, ExpiresAt: later})
	})
	wantEnd(later, "an approval for longer")
	asOwner(t, c, f, func(q *db.Queries) error {
		return q.ExtendGrant(ctx, &db.ExtendGrantParams{AccountID: f.account, UserID: f.u, ExpiresAt: soon})
	})
	wantEnd(later, "an approval for less shortened the grant")

	asOwner(t, c, f, func(q *db.Queries) error {
		return q.PutGrant(ctx, &db.PutGrantParams{
			AccountID: f.account, SubjectKind: db.SubjectKindUser, SubjectID: f.u, ExpiresAt: &soon,
		})
	})
	wantEnd(soon, "an admin's shorter end")

	asOwner(t, c, f, func(q *db.Queries) error {
		return q.PutGrant(
			ctx,
			&db.PutGrantParams{AccountID: f.account, SubjectKind: db.SubjectKindUser, SubjectID: f.u},
		)
	})
	end, _ := grantEnd(t, c, f)
	require.Nil(t, end, "an admin's grant for good still ends")
	asOwner(t, c, f, func(q *db.Queries) error {
		return q.ExtendGrant(ctx, &db.ExtendGrantParams{AccountID: f.account, UserID: f.u, ExpiresAt: soon})
	})
	end, _ = grantEnd(t, c, f)
	require.Nil(t, end, "an approval made a grant for good end")
}
