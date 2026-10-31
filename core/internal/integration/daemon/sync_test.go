//go:build integration

package daemon_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/daemon"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// reportFails runs the first transaction and refuses every one after, like a database that cannot take the report.
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

// A server always gets its principal list. What it reports about itself is saved after, and a failed save never
// stands in the way.
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
