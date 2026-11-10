//go:build integration

package daemon_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/protobuf/types/known/durationpb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/core/internal/crypto"
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

// One rollover reaches every daemon at its next sync, with the new keys only.
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
	before, err := daemon.Sync(f.ctx, f.conn, daemon.SyncInput{DaemonID: daemons[0]})
	require.NoError(t, err)

	var next *db.SSHCA
	require.NoError(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) error {
		current, err := q.GetWorkspaceCA(f.ctx)
		if err != nil {
			return err
		}
		next, err = ssh.Rollover(f.ctx, q, keys, current)
		return err
	}))

	for _, id := range daemons {
		res, err := daemon.Sync(f.ctx, f.conn, daemon.SyncInput{DaemonID: id})
		require.NoError(t, err)
		assert.Equal(t, next.PublicKey, res.GetCaPublicKey())
		assert.Equal(t, next.HostPublicKey, res.GetHostCaPublicKey())
		assert.NotEqual(t, before.GetStateHash(), res.GetStateHash(), "new keys must change the hash")
	}
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
	require.Len(t, res.GetPrincipals(), 1)
	assert.Equal(t, "dev", res.GetPrincipals()[0].GetUsername())
	assert.Len(t, readTarget(t, f, out.DaemonID).accounts, 1, "the report was saved after all")
}

// What a server is told to let in, with the cases a mistake would hide in: a team's members, a service account, a
// person switched off, a grant that ended, another server's grants, and a daemon that is pending or gone.
func TestSyncAnswer(t *testing.T) {
	f, token := enrollToken(t, func(p *db.CreateJoinTokenParams) { p.AutoApprove = true })
	teamID := seedTeamGrant(t, f, "dev")
	web, err := enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname("web")})
	require.NoError(t, err)
	db1, err := enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname("db")})
	require.NoError(t, err)

	var member, direct, bot, pendingToken string
	require.NoError(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) error {
		user := func(name string) string {
			u, err := q.CreateUser(f.ctx, &db.CreateUserParams{
				Email: name + "@example.com", Name: name, Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
			})
			require.NoError(t, err)
			return u.ID
		}
		accounts := map[string]string{}
		grant := func(targetID, username, kind, subject string, ends *time.Time) {
			key := targetID + "/" + username
			if accounts[key] == "" {
				account, err := q.CreateTargetAccount(f.ctx, &db.CreateTargetAccountParams{
					TargetID: targetID, Username: username,
				})
				require.NoError(t, err)
				accounts[key] = account.ID
			}
			require.NoError(t, q.PutGrant(f.ctx, &db.PutGrantParams{
				AccountID: accounts[key], SubjectKind: kind, SubjectID: subject, ExpiresAt: ends,
			}))
		}

		member = user("member")
		off := user("off")
		for _, id := range []string{member, off} {
			require.NoError(t, q.AddTeamMember(f.ctx, &db.AddTeamMemberParams{UserID: id, TeamID: teamID}))
		}
		require.NoError(t, q.SetUserActive(f.ctx, &db.SetUserActiveParams{ID: off, Active: false}))

		direct = user("direct")
		grant(web.TargetID, "root", db.SubjectKindUser, direct, nil)
		grant(web.TargetID, "root", db.SubjectKindUser, user("ended"), new(time.Now().Add(-time.Minute)))
		grant(db1.TargetID, "postgres", db.SubjectKindUser, user("elsewhere"), nil)
		bot, err = q.CreateServiceAccount(f.ctx, &db.CreateServiceAccountParams{
			Name: "deploy", Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER, Tags: []string{},
		})
		require.NoError(t, err)
		grant(web.TargetID, "root", db.SubjectKindServiceAccount, bot, nil)

		if _, err = q.UpdateWorkspace(f.ctx, &db.UpdateWorkspaceParams{
			Settings: &nokkuv1.WorkspaceSettings{SessionIdleTimeout: durationpb.New(10 * time.Minute)},
		}); err != nil {
			return err
		}
		params := &db.CreateJoinTokenParams{}
		pendingToken, params.TokenHash = crypto.NewToken(crypto.TokenEnroll)
		_, err = q.CreateJoinToken(f.ctx, params)
		return err
	}))

	res, err := daemon.Sync(f.ctx, f.conn, daemon.SyncInput{DaemonID: web.DaemonID})
	require.NoError(t, err)
	assert.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED, res.GetStatus())
	assert.Equal(t, "pub", res.GetCaPublicKey())
	assert.Equal(t, "host-pub", res.GetHostCaPublicKey())
	assert.Equal(t, 10*time.Minute, res.GetConfig().GetIdleTimeout().AsDuration(), "the workspace's idle timeout")
	got := map[string][]string{}
	for _, p := range res.GetPrincipals() {
		got[p.GetUsername()] = slices.Sorted(slices.Values(p.GetCertPrincipals()))
	}
	principals := func(username string, subjects ...string) []string {
		out := make([]string, 0, len(subjects))
		for _, id := range subjects {
			out = append(out, login.Principal(id, web.TargetID, username))
		}
		return slices.Sorted(slices.Values(out))
	}
	assert.Equal(t, map[string][]string{
		"dev":  principals("dev", member),
		"root": principals("root", direct, bot),
	}, got)

	// The same answer hashes the same, and a change for this server changes it.
	hash := res.GetStateHash()
	require.Len(t, hash, 32)
	res, err = daemon.Sync(f.ctx, f.conn, daemon.SyncInput{DaemonID: web.DaemonID})
	require.NoError(t, err)
	assert.Equal(t, hash, res.GetStateHash(), "nothing changed")
	other, err := daemon.Sync(f.ctx, f.conn, daemon.SyncInput{DaemonID: db1.DaemonID})
	require.NoError(t, err)
	assert.NotEqual(t, hash, other.GetStateHash(), "another server lets other people in")
	require.NoError(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) error {
		return q.SetUserActive(f.ctx, &db.SetUserActiveParams{ID: direct, Active: false})
	}))
	res, err = daemon.Sync(f.ctx, f.conn, daemon.SyncInput{DaemonID: web.DaemonID})
	require.NoError(t, err)
	assert.NotEqual(t, hash, res.GetStateHash(), "a person switched off must change it")

	// The pass over the workspace and a sync must agree, a poke compares the two.
	hashes, err := daemon.Hashes(f.ctx, f.conn)
	require.NoError(t, err)
	assert.Equal(t, res.GetStateHash(), hashes[web.DaemonID])
	assert.Equal(t, other.GetStateHash(), hashes[db1.DaemonID])

	waiting, err := enroll(t, f, daemon.EnrollInput{Token: pendingToken, ReqMetadata: hostname("new")})
	require.NoError(t, err)
	res, err = daemon.Sync(f.ctx, f.conn, daemon.SyncInput{DaemonID: waiting.DaemonID})
	require.NoError(t, err)
	assert.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING, res.GetStatus())
	assert.Empty(t, res.GetPrincipals(), "a pending daemon lets nobody in")
	assert.Empty(t, res.GetCaPublicKey(), "a pending daemon trusts no CA")

	require.NoError(t, f.conn.TenantTx(f.ctx, func(q *db.Queries) error {
		_, err := q.DeleteDaemon(f.ctx, db1.DaemonID)
		return err
	}))
	res, err = daemon.Sync(f.ctx, f.conn, daemon.SyncInput{DaemonID: db1.DaemonID})
	require.NoError(t, err)
	assert.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_REJECTED, res.GetStatus(), "a deleted daemon is told to stop")
}
