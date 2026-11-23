//go:build integration

package api_test

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/app"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// A grant on a tag is one call, one transaction and one access change, however many servers. The plan says first
// what the grant then does.
func TestGrantOnATag(t *testing.T) {
	// Licensed, a grant with an end is a paid feature.
	cfg, srv := enterprise(t)
	ws := testWorkspace.ID
	api := nokkuv1connect.NewTargetAccountServiceClient(clientOn(srv, header("Authorization",
		"Bearer "+seedMember(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR))))
	tag, other := uniq("fleet"), uniq("other")
	const servers, without = 30, 2

	var team string
	accounts := map[string]string{}
	inWorkspace(t, cfg, ws, func(q *db.Queries) error {
		created, err := q.CreateTeam(t.Context(), &db.CreateTeamParams{Name: uniq("oncall"), Tags: []string{}})
		if err != nil {
			return err
		}
		team = created.ID
		for i := range servers {
			target, err := q.CreateTarget(t.Context(), &db.CreateTargetParams{
				Name: fmt.Sprintf("%s-%02d", tag, i), Tags: []string{tag}, Endpoints: []string{},
			})
			if err != nil {
				return err
			}
			if i < without {
				continue
			}
			account, err := q.CreateTargetAccount(t.Context(), &db.CreateTargetAccountParams{
				TargetID: target.ID, Username: "deploy",
			})
			if err != nil {
				return err
			}
			accounts[target.ID] = account.ID
		}
		// A server with another tag is none of this grant's business.
		_, err = q.CreateTarget(t.Context(), &db.CreateTargetParams{
			Name: other, Tags: []string{other}, Endpoints: []string{},
		})
		return err
	})
	person := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	spec := func(change func(*nokkuv1.GrantSpec)) *nokkuv1.GrantSpec {
		s := &nokkuv1.GrantSpec{
			Subjects: []*nokkuv1.GrantSubject{
				{Id: &team, Kind: nokkuv1.SubjectKind_SUBJECT_KIND_TEAM.Enum()},
				{Id: &person.ID, Kind: nokkuv1.SubjectKind_SUBJECT_KIND_USER.Enum()},
			},
			Tags:     []string{tag},
			Username: new("deploy"),
		}
		if change != nil {
			change(s)
		}
		return s
	}
	plan := func(s *nokkuv1.GrantSpec) *nokkuv1.GrantPlan {
		t.Helper()
		res, err := api.Grant(t.Context(), &nokkuv1.GrantRequest{Grant: s, DryRun: new(true)})
		require.NoError(t, err)
		return res.GetPlan()
	}
	grants := func() int {
		var count int
		inWorkspace(t, cfg, ws, func(q *db.Queries) error {
			for _, account := range accounts {
				ends, err := q.ListGrantEnds(t.Context(), &db.ListGrantEndsParams{
					AccountIds: []string{account}, SubjectID: team,
				})
				if err != nil {
					return err
				}
				count += len(ends)
			}
			return nil
		})
		return count
	}
	outcome := func(p *nokkuv1.GrantPlan, i int) [3]int32 {
		t.Helper()
		require.Len(t, p.GetOutcomes(), 2)
		o := p.GetOutcomes()[i]
		return [3]int32{o.GetAdded(), o.GetSame(), o.GetOtherEnd()}
	}

	// With no account asked for, the plan only says which servers these are and what accounts they have.
	asked := plan(spec(func(s *nokkuv1.GrantSpec) { s.Username = nil }))
	assert.EqualValues(t, servers, asked.GetServers())
	assert.Len(t, asked.GetServerNames(), 5, "a few names stand for the rest")
	require.Len(t, asked.GetAccounts(), 1)
	assert.Equal(t, "deploy", asked.GetAccounts()[0].GetUsername())
	assert.EqualValues(t, servers-without, asked.GetAccounts()[0].GetServers())

	before := plan(spec(nil))
	assert.EqualValues(t, servers-without, before.GetWithAccount())
	assert.Len(t, before.GetSkipped(), without, "the servers without the account are named")
	assert.Equal(t, [3]int32{servers - without, 0, 0}, outcome(before, 0))
	assert.Zero(t, grants(), "the plan wrote something")

	listener, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close(context.WithoutCancel(t.Context())) })
	_, err = listener.Exec(t.Context(), "LISTEN nokku_state")
	require.NoError(t, err)

	done, err := api.Grant(t.Context(), &nokkuv1.GrantRequest{Grant: spec(nil)})
	require.NoError(t, err)
	assert.Equal(t, outcome(before, 0), outcome(done.GetPlan(), 0), "the grant did something else than its plan")
	assert.Equal(t, servers-without, grants())
	told := 0
	for {
		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		note, waitErr := listener.WaitForNotification(ctx)
		cancel()
		if waitErr != nil {
			break
		}
		if note.Payload == ws {
			told++
		}
	}
	assert.Equal(t, 1, told, "56 new grants must be one access change")

	// Again it has nothing to do. With an end it leaves the grants that stand alone, unless asked to move them.
	assert.Equal(t, [3]int32{0, servers - without, 0}, outcome(plan(spec(nil)), 0))
	end := timestamppb.New(time.Now().Add(time.Hour))
	timed := func(s *nokkuv1.GrantSpec) { s.ExpiresAt = end }
	assert.Equal(t, [3]int32{0, 0, servers - without}, outcome(plan(spec(timed)), 1))
	_, err = api.Grant(t.Context(), &nokkuv1.GrantRequest{Grant: spec(timed)})
	require.NoError(t, err)
	assert.Equal(
		t,
		[3]int32{0, servers - without, 0},
		outcome(plan(spec(nil)), 1),
		"a standing grant got an end unasked",
	)
	_, err = api.Grant(t.Context(), &nokkuv1.GrantRequest{Grant: spec(func(s *nokkuv1.GrantSpec) {
		s.ExpiresAt, s.ChangeEnds = end, new(true)
	})})
	require.NoError(t, err)
	assert.Equal(t, [3]int32{0, servers - without, 0}, outcome(plan(spec(timed)), 1), "the ends did not move")
}

// A revoke on a tag takes the subject's own grants there in one call and one access change. Grants of others and
// grants on other servers stay.
func TestRevokeOnATag(t *testing.T) {
	cfg, srv := enterprise(t)
	ws := testWorkspace.ID
	editor := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR)
	api := nokkuv1connect.NewTargetAccountServiceClient(clientOn(srv, header("Authorization",
		"Bearer "+sessionFor(t, cfg, editor))))
	tag, second := uniq("fleet"), uniq("second")
	person := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)

	var team, outside, outsideServer string
	var onTag []string
	inWorkspace(t, cfg, ws, func(q *db.Queries) error {
		created, err := q.CreateTeam(t.Context(), &db.CreateTeamParams{Name: uniq("oncall"), Tags: []string{}})
		if err != nil {
			return err
		}
		team = created.ID
		account := func(name string, tags []string, usernames ...string) (string, []string, error) {
			target, err := q.CreateTarget(t.Context(), &db.CreateTargetParams{
				Name: name, Tags: tags, Endpoints: []string{},
			})
			if err != nil {
				return "", nil, err
			}
			var ids []string
			for _, username := range usernames {
				a, err := q.CreateTargetAccount(t.Context(), &db.CreateTargetAccountParams{
					TargetID: target.ID, Username: username,
				})
				if err != nil {
					return "", nil, err
				}
				ids = append(ids, a.ID)
			}
			return target.ID, ids, nil
		}
		// Three servers on the tag, one has root too and a second tag.
		for i, s := range []struct {
			tags      []string
			usernames []string
		}{
			{[]string{tag, second}, []string{"deploy", "root"}},
			{[]string{tag}, []string{"deploy"}},
			{[]string{tag}, []string{"deploy"}},
		} {
			_, ids, err := account(fmt.Sprintf("%s-%d", tag, i), s.tags, s.usernames...)
			if err != nil {
				return err
			}
			onTag = append(onTag, ids...)
		}
		serverID, ids, err := account(uniq("elsewhere"), []string{}, "deploy")
		if err != nil {
			return err
		}
		outsideServer, outside = serverID, ids[0]
		if err := q.PutGrants(t.Context(), &db.PutGrantsParams{
			AccountIds: append(slices.Clone(onTag), outside), SubjectKind: db.SubjectKindTeam, SubjectID: team,
		}); err != nil {
			return err
		}
		return q.PutGrants(t.Context(), &db.PutGrantsParams{
			AccountIds: []string{onTag[0]}, SubjectKind: db.SubjectKindUser, SubjectID: person.ID,
		})
	})
	held := func(subject string, accounts ...string) int {
		var count int
		inWorkspace(t, cfg, ws, func(q *db.Queries) error {
			ends, err := q.ListGrantEnds(t.Context(), &db.ListGrantEndsParams{
				AccountIds: accounts, SubjectID: subject,
			})
			count = len(ends)
			return err
		})
		return count
	}
	spec := &nokkuv1.RevokeSpec{
		Subject: &nokkuv1.GrantSubject{Id: &team, Kind: nokkuv1.SubjectKind_SUBJECT_KIND_TEAM.Enum()},
		Tags:    []string{tag},
	}

	// One account of the tag's servers goes alone when it is named.
	onlyRoot, err := api.Revoke(t.Context(), &nokkuv1.RevokeRequest{DryRun: new(true), Revoke: &nokkuv1.RevokeSpec{
		Subject: spec.GetSubject(), Tags: spec.GetTags(), Username: new("root"),
	}})
	require.NoError(t, err)
	assert.EqualValues(t, 1, onlyRoot.GetPlan().GetGrants())
	// Nor does a revoke with no server named take anything.
	nowhere, err := api.Revoke(t.Context(), &nokkuv1.RevokeRequest{DryRun: new(true), Revoke: &nokkuv1.RevokeSpec{
		Subject: spec.GetSubject(),
	}})
	require.NoError(t, err)
	assert.Zero(t, nowhere.GetPlan().GetGrants(), "no server named must mean none, not all")

	planned, err := api.Revoke(t.Context(), &nokkuv1.RevokeRequest{Revoke: spec, DryRun: new(true)})
	require.NoError(t, err)
	plan := planned.GetPlan()
	assert.EqualValues(t, 4, plan.GetGrants())
	assert.EqualValues(t, 3, plan.GetServers())
	require.Len(t, plan.GetAccounts(), 2)
	assert.Equal(t, "deploy", plan.GetAccounts()[0].GetUsername(), "the account on the most servers comes first")
	assert.EqualValues(t, 3, plan.GetAccounts()[0].GetServers())
	assert.Len(t, plan.GetAccounts()[0].GetServerNames(), 3)
	assert.Equal(t, "root", plan.GetAccounts()[1].GetUsername())
	assert.EqualValues(t, 1, plan.GetOtherTags())
	assert.Equal(t, []string{tag + "-0"}, plan.GetOtherTagNames())
	assert.Equal(t, 4, held(team, onTag...), "the plan took something")

	listener, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close(context.WithoutCancel(t.Context())) })
	_, err = listener.Exec(t.Context(), "LISTEN nokku_state")
	require.NoError(t, err)

	done, err := api.Revoke(t.Context(), &nokkuv1.RevokeRequest{Revoke: spec})
	require.NoError(t, err)
	assert.EqualValues(t, 4, done.GetPlan().GetGrants(), "the revoke did something else than its plan")
	told := 0
	for {
		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		note, waitErr := listener.WaitForNotification(ctx)
		cancel()
		if waitErr != nil {
			break
		}
		if note.Payload == ws {
			told++
		}
	}
	assert.Equal(t, 1, told, "four grants gone must be one access change")
	assert.Zero(t, held(team, onTag...))
	assert.Equal(t, 1, held(person.ID, onTag[0]), "someone else's grant went along")
	assert.Equal(t, 1, held(team, outside), "a grant on a server without the tag went along")

	again, err := api.Revoke(t.Context(), &nokkuv1.RevokeRequest{Revoke: spec, DryRun: new(true)})
	require.NoError(t, err)
	assert.Zero(t, again.GetPlan().GetGrants())

	// The whole revoke is one audit event about the team. It says how much went and from where.
	var events []*db.ListAuditLogsRow
	require.Eventually(t, func() bool {
		inWorkspace(t, cfg, ws, func(q *db.Queries) (err error) {
			events, err = q.ListAuditLogs(t.Context(), &db.ListAuditLogsParams{Target: &team, Limit: 5})
			return err
		})
		return len(events) == 1
	}, 5*time.Second, 20*time.Millisecond, "the revoke must leave one audit event")
	assert.Equal(t, "Revoke", events[0].Action)
	// The dry runs before and after it changed nothing, so they left no event.
	inWorkspace(t, cfg, ws, func(q *db.Queries) (err error) {
		events, err = q.ListAuditLogs(t.Context(), &db.ListAuditLogsParams{
			ActorIds: []string{editor.ID}, Actions: []string{"Grant", "Revoke"}, Limit: 5,
		})
		return err
	})
	assert.Len(t, events, 1, "a dry run was written to the audit log")
	var details struct {
		Removed   int      `json:"removed"`
		Servers   int      `json:"servers"`
		Usernames []string `json:"usernames"`
		Tags      []string `json:"tags"`
	}
	require.NoError(t, json.Unmarshal(events[0].Details, &details))
	assert.Equal(t, 4, details.Removed)
	assert.Equal(t, 3, details.Servers)
	assert.Equal(t, []string{"deploy", "root"}, details.Usernames)
	assert.Equal(t, []string{tag}, details.Tags)

	// A server goes by id as well.
	_, err = api.Revoke(t.Context(), &nokkuv1.RevokeRequest{Revoke: &nokkuv1.RevokeSpec{
		Subject:   spec.GetSubject(),
		TargetIds: []string{outsideServer},
	}})
	require.NoError(t, err)
	assert.Zero(t, held(team, outside))
}

// A dry run leaves no audit row, not even when it is refused.
func TestADryRunLeavesNoAuditRow(t *testing.T) {
	cfg, srv := enterprise(t)
	ws := testWorkspace.ID
	editor := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR)
	member := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	as := func(u *db.User) nokkuv1connect.TargetAccountServiceClient {
		return nokkuv1connect.NewTargetAccountServiceClient(clientOn(srv, header("Authorization",
			"Bearer "+sessionFor(t, cfg, u))))
	}
	spec := &nokkuv1.GrantSpec{
		Subjects:  []*nokkuv1.GrantSubject{{Id: &member.ID, Kind: nokkuv1.SubjectKind_SUBJECT_KIND_USER.Enum()}},
		Tags:      []string{uniq("none")},
		Username:  new("deploy"),
		ExpiresAt: timestamppb.New(time.Now().Add(-time.Minute)),
	}
	_, err := as(editor).Grant(t.Context(), &nokkuv1.GrantRequest{Grant: spec, DryRun: new(true)})
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "an end in the past: %v", err)
	_, err = as(member).Revoke(t.Context(), &nokkuv1.RevokeRequest{DryRun: new(true), Revoke: &nokkuv1.RevokeSpec{
		Subject: spec.GetSubjects()[0], Everywhere: new(true),
	}})
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "a member's revoke: %v", err)

	var rows []*db.ListAuditLogsRow
	inWorkspace(t, cfg, ws, func(q *db.Queries) (err error) {
		rows, err = q.ListAuditLogs(t.Context(), &db.ListAuditLogsParams{
			ActorIds: []string{editor.ID, member.ID}, Actions: []string{"Grant", "Revoke"}, Limit: 5,
		})
		return err
	})
	assert.Empty(t, rows, "a dry run was written to the audit log")
}

// grantAccount gives subjects one account of one server, for good.
func grantAccount(
	t *testing.T, c nokkuv1connect.TargetAccountServiceClient, targetID, username string,
	kind nokkuv1.SubjectKind, subjects ...string,
) {
	t.Helper()
	spec := &nokkuv1.GrantSpec{TargetIds: []string{targetID}, Username: &username}
	for _, id := range subjects {
		spec.Subjects = append(spec.Subjects, &nokkuv1.GrantSubject{Id: &id, Kind: kind.Enum()})
	}
	res, err := c.Grant(t.Context(), &nokkuv1.GrantRequest{Grant: spec})
	require.NoError(t, err)
	require.EqualValues(t, 1, res.GetPlan().GetWithAccount(), "the server has no %s account", username)
}

// revokeAccount takes a subject's own grant on one account of one server.
func revokeAccount(
	t *testing.T, c nokkuv1connect.TargetAccountServiceClient, targetID, username string,
	kind nokkuv1.SubjectKind, subject string,
) {
	t.Helper()
	_, err := c.Revoke(t.Context(), &nokkuv1.RevokeRequest{Revoke: &nokkuv1.RevokeSpec{
		Subject:   &nokkuv1.GrantSubject{Id: &subject, Kind: kind.Enum()},
		TargetIds: []string{targetID},
		Username:  &username,
	}})
	require.NoError(t, err)
}

// grantedBy reads who a grant on a server names, no query returns it yet.
func grantedBy(t *testing.T, cfg *app.Config, targetID, subjectID string) string {
	t.Helper()
	var by string
	require.NoError(t, cfg.Conn.Pool.QueryRow(wsCtx(t), `
		SELECT g.granted_by FROM grants g JOIN target_accounts a ON a.id = g.account_id
		WHERE a.target_id = $1 AND g.subject_id = $2`, targetID, subjectID).Scan(&by), "read who granted")
	return by
}

// The access matrix will show who granted, so every way to grant stores it.
func TestGrantsNameWhoMadeThem(t *testing.T) {
	cfg, srv := enterprise(t)
	ws := testWorkspace.ID
	editor := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR)
	client := clientOn(srv, header("Authorization", "Bearer "+sessionFor(t, cfg, editor)))
	accounts := nokkuv1connect.NewTargetAccountServiceClient(client)
	one := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	two := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	tag := uniq("named")

	var target string
	inWorkspace(t, cfg, ws, func(q *db.Queries) error {
		created, err := q.CreateTarget(t.Context(), &db.CreateTargetParams{
			Name: uniq("named"), Tags: []string{tag}, Endpoints: []string{},
		})
		if err != nil {
			return err
		}
		target = created.ID
		_, err = q.CreateTargetAccount(t.Context(), &db.CreateTargetAccountParams{
			TargetID: target, Username: "deploy",
		})
		return err
	})

	grantAccount(t, accounts, target, "deploy", nokkuv1.SubjectKind_SUBJECT_KIND_USER, one.ID)
	assert.Equal(t, editor.ID, grantedBy(t, cfg, target, one.ID), "a grant on one server left the grant unnamed")

	_, err := accounts.Grant(t.Context(), &nokkuv1.GrantRequest{Grant: &nokkuv1.GrantSpec{
		Subjects: []*nokkuv1.GrantSubject{{Id: &two.ID, Kind: nokkuv1.SubjectKind_SUBJECT_KIND_USER.Enum()}},
		Tags:     []string{tag},
		Username: new("deploy"),
	}})
	require.NoError(t, err)
	assert.Equal(t, editor.ID, grantedBy(t, cfg, target, two.ID), "Grant left the grant unnamed")

	seeded, err := nokkuv1connect.NewTargetServiceClient(client).CreateTarget(t.Context(), &nokkuv1.CreateTargetRequest{
		Name:   new(uniq("named")),
		Grants: []*nokkuv1.JoinTokenGrant{{Username: new("root"), UserIds: []string{one.ID}}},
	})
	require.NoError(t, err)
	assert.Equal(
		t, editor.ID, grantedBy(t, cfg, seeded.GetTarget().GetId(), one.ID), "CreateTarget left the grant unnamed",
	)
}
