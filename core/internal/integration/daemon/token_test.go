//go:build integration

package daemon_test

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/daemon"
	"github.com/nokku-sh/nokku/core/internal/db"
)

var generatedName = regexp.MustCompile(`^[a-z]+-[a-z]+$`)

type seededTarget struct {
	target   *db.Target
	accounts []*db.GetTargetAccountsByTargetIDsRow
}

// seedTeamGrant grants username to a fresh team on the token, returns its id.
func seedTeamGrant(t *testing.T, f fixture, username string) string {
	t.Helper()
	var teamID string
	require.NoError(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) error {
		team, err := q.CreateTeam(f.ctx, &db.CreateTeamParams{Name: "backend", Tags: []string{}})
		if err != nil {
			return err
		}
		teamID = team.ID
		tokens, err := q.ListJoinTokens(f.ctx)
		if err != nil {
			return err
		}
		return q.AddJoinTokenGrant(f.ctx, &db.AddJoinTokenGrantParams{
			TokenID: tokens[0].ID, Username: username, SubjectKind: db.SubjectKindTeam, SubjectID: teamID,
		})
	}))
	return teamID
}

func readTarget(t *testing.T, f fixture, daemonID string) seededTarget {
	t.Helper()
	var out seededTarget
	require.NoError(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) (err error) {
		if out.target, err = q.GetTargetByDaemon(f.ctx, &daemonID); err != nil {
			return err
		}
		out.accounts, err = q.GetTargetAccountsByTargetIDs(f.ctx, []string{out.target.ID})
		return err
	}))
	return out
}

func hostname(name string) map[string]string {
	return map[string]string{"hostname": name, "os": "linux"}
}

// The token's grants and tags land on the target once. A re-enroll does not
// undo a later change in the web app.
func TestEnrollSeedsTokenGrantsOnce(t *testing.T) {
	f, token := enrollToken(t, func(p *db.CreateJoinTokenParams) { p.Tags = []string{"sandbox"} })
	teamID := seedTeamGrant(t, f, "dev")

	in := daemon.EnrollInput{Token: token, Binding: "machine-key", ReqMetadata: hostname("alice")}
	out, err := enroll(t, f, in)
	require.NoError(t, err)
	assert.Equal(t, "alice", out.Name)
	assert.False(t, out.Config.GetEphemeral())

	seeded := readTarget(t, f, out.DaemonID)
	assert.Equal(t, []string{"sandbox"}, seeded.target.Tags)
	require.Len(t, seeded.accounts, 1)
	assert.Equal(t, "dev", seeded.accounts[0].TargetAccount.Username)
	assert.Equal(t, []string{teamID}, seeded.accounts[0].TeamIds)
	assert.Nil(t, seeded.accounts[0].TargetAccount.SeenAt, "the host has not reported dev yet")

	require.NoError(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) error {
		return q.RemoveGrant(f.ctx, &db.RemoveGrantParams{
			AccountID: seeded.accounts[0].TargetAccount.ID, SubjectKind: db.SubjectKindTeam, SubjectID: teamID,
		})
	}))
	reenrolled, err := enroll(t, f, in)
	require.NoError(t, err)
	assert.Equal(t, out.DaemonID, reenrolled.DaemonID)
	assert.Empty(t, readTarget(t, f, out.DaemonID).accounts[0].TeamIds, "the re-enroll put the grant back")
}

// A hostname a person chose is the name. A default or taken one is generated.
func TestEnrollNamesFromHostname(t *testing.T) {
	f, token := enrollToken(t, nil)

	cloud, err := enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname("ip-10-0-1-23")})
	require.NoError(t, err)
	assert.Regexp(t, generatedName, cloud.Name)

	web, err := enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname("web-1.internal")})
	require.NoError(t, err)
	assert.Equal(t, "web-1", web.Name)

	twin, err := enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname("web-1")})
	require.NoError(t, err)
	assert.Regexp(t, generatedName, twin.Name, "a taken name falls back to the generator")

	require.NoError(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) error {
		_, err := q.CreateTarget(f.ctx, &db.CreateTargetParams{Name: "alice", Tags: []string{}, Metadata: []byte(`{}`)})
		return err
	}))
	manual, err := enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname("alice")})
	require.NoError(t, err)
	assert.Regexp(t, generatedName, manual.Name, "a manual target holds the name")
}

func ephemeralToken(t *testing.T, retireAfter time.Duration) (fixture, string) {
	t.Helper()
	return enrollToken(t, func(p *db.CreateJoinTokenParams) {
		p.AutoApprove = true
		p.RetireAfter = &retireAfter
	})
}

// An ephemeral box back under its name replaces the one that went away, not a
// live one.
func TestEnrollEphemeralReplacesOffline(t *testing.T) {
	f, token := ephemeralToken(t, 10*time.Minute)

	first, err := enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname("alice")})
	require.NoError(t, err)
	assert.Equal(t, "alice", first.Name)
	assert.True(t, first.Config.GetEphemeral())

	second, err := enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname("alice")})
	require.NoError(t, err)
	assert.Equal(t, "alice", second.Name)
	require.NoError(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) error {
		_, err := q.GetDaemon(f.ctx, first.DaemonID)
		assert.Error(t, err, "the offline daemon of that name is gone")
		return nil
	}))

	third, err := enroll(t, f, daemon.EnrollInput{
		Token: token, ReqMetadata: hostname("alice"), Connected: []string{second.DaemonID},
	})
	require.NoError(t, err)
	assert.Regexp(t, generatedName, third.Name, "an online daemon keeps its name")
	require.NoError(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) error {
		_, err := q.GetDaemon(f.ctx, second.DaemonID)
		return err
	}))
}

// A container coming or going wakes nobody, or a busy fleet would sync without
// end. The version still moves, so every daemon catches up at its next
// heartbeat, and a real change wakes them all at once.
func TestContainerChurnWakesNobody(t *testing.T) {
	f, token := ephemeralToken(t, 10*time.Minute)
	teamID := seedTeamGrant(t, f, "deploy")
	workspaceID := actor.WorkspaceIDFromContext(f.ctx)

	listener, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close(context.WithoutCancel(t.Context())) })
	_, err = listener.Exec(t.Context(), "LISTEN nokku_state")
	require.NoError(t, err)
	woken := func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		defer cancel()
		for {
			n, err := listener.WaitForNotification(ctx)
			if err != nil {
				return false
			}
			if n.Payload == workspaceID {
				return true
			}
		}
	}
	version := func() int64 {
		v, err := f.conn.Sys().GetWorkspaceStateVersion(t.Context(), workspaceID)
		require.NoError(t, err)
		return v
	}

	before := version()
	_, err = enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname("alice")})
	require.NoError(t, err)
	assert.False(t, woken(), "a new container woke the fleet")
	assert.Greater(t, version(), before, "the version must move, the heartbeat is the backstop")

	before = version()
	_, err = enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname("alice")})
	require.NoError(t, err)
	assert.False(t, woken(), "a container replacing its offline self woke the fleet")
	assert.Greater(t, version(), before)

	require.NoError(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) error {
		return q.RevokeSubjectAccessInWorkspace(f.ctx, &db.RevokeSubjectAccessInWorkspaceParams{
			SubjectKind: db.SubjectKindTeam, SubjectID: teamID,
		})
	}))
	assert.True(t, woken(), "a revoke must wake the fleet at once")
}

// A leaked token that ran out must not delete an offline daemon by naming it.
func TestSpentTokenReplacesNothing(t *testing.T) {
	retire, uses := 10*time.Minute, int32(1)
	f, token := enrollToken(t, func(p *db.CreateJoinTokenParams) {
		p.AutoApprove = true
		p.RetireAfter = &retire
		p.MaxUses = &uses
	})
	first, err := enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname("alice")})
	require.NoError(t, err)

	_, err = enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname("alice")})
	require.ErrorIs(t, err, daemon.ErrEnrollToken, "a spent token enrolled a daemon")
	assert.NoError(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) error {
		_, err := q.GetDaemon(f.ctx, first.DaemonID)
		return err
	}), "a spent token deleted the offline daemon of that name")
}

// The sweep deletes an ephemeral daemon once away past retire_after, only then.
func TestRetireSweep(t *testing.T) {
	f, token := ephemeralToken(t, time.Second)
	out, err := enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname("alice")})
	require.NoError(t, err)

	// The sweep spans workspaces, only this daemon counts.
	var events []*audit.Event
	record := func(_ context.Context, e *audit.Event) {
		if e.Target == out.DaemonID {
			events = append(events, e)
		}
	}

	require.NoError(t, daemon.Retire(f.ctx, f.conn, nil, time.Time{}, record))
	assert.Empty(t, events, "retired a daemon that was just made")

	time.Sleep(1100 * time.Millisecond)
	require.NoError(t, daemon.Retire(f.ctx, f.conn, nil, time.Time{}, record))
	require.Len(t, events, 1)
	assert.Equal(t, "RetireDaemon", events[0].Action)
	require.Error(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) error {
		_, err := q.GetDaemon(f.ctx, out.DaemonID)
		return err
	}), "the daemon is still there")
}

// A daemon that stays connected is never away, however long ago it connected.
func TestRetireSweepKeepsAConnectedDaemon(t *testing.T) {
	f, token := ephemeralToken(t, time.Second)
	out, err := enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname("alice")})
	require.NoError(t, err)
	require.NoError(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) error {
		return q.MarkDaemonSeen(f.ctx, out.DaemonID)
	}))

	time.Sleep(1100 * time.Millisecond)
	var events []*audit.Event
	record := func(_ context.Context, e *audit.Event) { events = append(events, e) }
	require.NoError(t, daemon.Retire(f.ctx, f.conn, []string{out.DaemonID}, time.Time{}, record))
	assert.Empty(t, events, "retired a daemon that is connected")
	require.NoError(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) error {
		_, err := q.GetDaemon(f.ctx, out.DaemonID)
		return err
	}), "the connected daemon is gone")
}

// A crash stamps no daemon as gone, so one that was connected looks away since
// it connected. The sweep counts from the restart, so a daemon still
// reconnecting gets its whole retire_after.
func TestRetireSweepCountsFromTheRestart(t *testing.T) {
	f, token := ephemeralToken(t, time.Second)
	out, err := enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname("alice")})
	require.NoError(t, err)
	require.NoError(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) error {
		return q.MarkDaemonSeen(f.ctx, out.DaemonID)
	}))

	time.Sleep(1100 * time.Millisecond)
	restarted := time.Now()
	// The sweep spans workspaces, only this daemon counts.
	var retired []string
	record := func(_ context.Context, e *audit.Event) { retired = append(retired, e.Target) }
	require.NoError(t, daemon.Retire(f.ctx, f.conn, nil, restarted, record))
	assert.NotContains(t, retired, out.DaemonID, "retired a daemon right after the restart")

	time.Sleep(1100 * time.Millisecond)
	require.NoError(t, daemon.Retire(f.ctx, f.conn, nil, restarted, record))
	assert.Contains(t, retired, out.DaemonID, "a daemon that never came back stays")
}
