//go:build integration

package daemon_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/crypto/kms"
	"github.com/nokku-sh/nokku/core/internal/daemon"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/ssh"
)

// reportFails runs the first transaction and refuses the rest.
type reportFails struct {
	*db.Connection

	txs int
}

func (c *reportFails) TenantTx(ctx context.Context, fn func(*db.Queries) error) error {
	if c.txs++; c.txs > 1 {
		return errors.New("the report write failed")
	}
	return c.Connection.TenantTx(ctx, fn)
}

// One rollover reaches every daemon at its next sync. A routine one keeps the
// old key trusted for a while, an emergency one drops it at once.
func TestRolloverReachesTheNextSync(t *testing.T) {
	f, token := enrollToken(t, func(p *db.CreateJoinTokenParams) { p.AutoApprove = true })
	daemons := make([]string, 0, 2)
	for _, name := range []string{"alice", "bob"} {
		out, err := enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname(name)})
		require.NoError(t, err)
		daemons = append(daemons, out.DaemonID)
	}
	keys, err := kms.Ephemeral()
	require.NoError(t, err)
	rollover := func(revoke bool) (replaced, next *db.SSHCA) {
		require.NoError(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) (err error) {
			if replaced, err = q.GetWorkspaceCA(f.ctx); err != nil {
				return err
			}
			next, err = ssh.Rollover(f.ctx, q, keys, replaced, revoke)
			return err
		}))
		return replaced, next
	}
	syncAll := func(check func(*daemon.Synced)) {
		for _, id := range daemons {
			res, err := daemon.Sync(f.ctx, f.conn, daemon.SyncInput{DaemonID: id})
			require.NoError(t, err)
			check(res)
		}
	}
	var version int64
	syncAll(func(res *daemon.Synced) { version = res.Version })

	replaced, next := rollover(false)
	syncAll(func(res *daemon.Synced) {
		assert.Greater(t, res.Version, version, "a rollover must wake the daemons")
		assert.Equal(t, next.PublicKey, res.CAPublicKey)
		assert.Equal(t, next.HostPublicKey, res.HostCAPublicKey)
		require.Len(t, res.RetiredCAs, 1, "a routine rollover keeps the old key trusted")
		assert.Equal(t, replaced.PublicKey, res.RetiredCAs[0].GetPublicKey())
		assert.WithinDuration(t, *next.PreviousTrustedUntil, res.RetiredCAs[0].GetTrustedUntil().AsTime(), time.Second)
	})

	_, next = rollover(true)
	syncAll(func(res *daemon.Synced) {
		assert.Equal(t, next.PublicKey, res.CAPublicKey)
		assert.Empty(t, res.RetiredCAs, "an emergency rollover ends the old trust at the next sync")
	})
}

// A server always gets its principals. Its report is saved after, a failed save
// never stands in the way.
func TestSyncAnswersWhenTheReportCannotBeSaved(t *testing.T) {
	f, token := enrollToken(t, func(p *db.CreateJoinTokenParams) { p.AutoApprove = true })
	teamID := seedTeamGrant(t, f, "dev")
	require.NoError(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) error {
		u, err := q.CreateUser(f.ctx, &db.CreateUserParams{
			Email: "dev@example.com", Name: "Dev", Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
		})
		if err != nil {
			return err
		}
		return q.AddTeamMember(f.ctx, &db.AddTeamMemberParams{UserID: u.ID, TeamID: teamID})
	}))
	out, err := enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname("alice")})
	require.NoError(t, err)

	res, err := daemon.Sync(f.ctx, &reportFails{Connection: f.conn}, daemon.SyncInput{
		DaemonID: out.DaemonID, Users: []string{"dev", "ops"},
	})
	require.NoError(t, err)
	require.Len(t, res.Principals, 1)
	assert.Equal(t, "dev", res.Principals[0].GetUsername())
	assert.Len(t, readTarget(t, f, out.DaemonID).accounts, 1, "the report was saved after all")
}
