//go:build integration

package daemon_test

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/daemon"
	"github.com/nokku-sh/nokku/core/internal/db"
)

var generatedName = regexp.MustCompile(`^[a-z]+-[a-z]+$`)

// seedTeamGrant gives the token a grant of username to a fresh team and returns the team id.
func seedTeamGrant(t *testing.T, f fixture, username string) string {
	t.Helper()
	var teamID string
	require.NoError(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) error {
		team, err := q.CreateTeam(f.ctx, &db.CreateTeamParams{Name: "backend", Tags: []string{}})
		if err != nil {
			return err
		}
		teamID = team.ID
		tokens, err := q.ListJoinTokens(f.ctx, 0)
		if err != nil {
			return err
		}
		return q.AddJoinTokenGrant(f.ctx, &db.AddJoinTokenGrantParams{
			TokenID: tokens[0].ID, Username: username, SubjectKind: db.SubjectKindTeam, SubjectID: teamID,
		})
	}))
	return teamID
}

type seededTarget struct {
	target   *db.Target
	accounts []*db.GetTargetAccountsByTargetIDsRow
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

// The token's grants and tags land on the target once. A later change in the web app is not undone by a re-enroll.
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

// A hostname a person chose becomes the name. A default one, or a taken one, gets a generated name instead.
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

// An ephemeral box that comes back under its name replaces the one that went away. A live one keeps its name.
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
		return q.TouchDaemons(f.ctx, []string{second.DaemonID})
	}))

	third, err := enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname("alice")})
	require.NoError(t, err)
	assert.Regexp(t, generatedName, third.Name, "an online daemon keeps its name")
	require.NoError(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) error {
		_, err := q.GetDaemon(f.ctx, second.DaemonID)
		return err
	}))
}

// The sweep deletes an ephemeral daemon once it has been away longer than retire_after, and only then.
func TestRetireSweep(t *testing.T) {
	f, token := ephemeralToken(t, time.Second)
	out, err := enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname("alice")})
	require.NoError(t, err)

	var events []*audit.Event
	record := func(_ context.Context, e *audit.Event) { events = append(events, e) }

	require.NoError(t, daemon.Retire(f.ctx, f.conn, record))
	assert.Empty(t, events, "retired a daemon that was just made")

	time.Sleep(1100 * time.Millisecond)
	require.NoError(t, daemon.Retire(f.ctx, f.conn, record))
	require.Len(t, events, 1)
	assert.Equal(t, "RetireDaemon", events[0].Action)
	assert.Equal(t, out.DaemonID, events[0].Target)
	require.Error(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) error {
		_, err := q.GetDaemon(f.ctx, out.DaemonID)
		return err
	}), "the daemon is still there")
}
