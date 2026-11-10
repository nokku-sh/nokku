//go:build integration

package api_test

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

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
		res, err := api.PlanGrant(t.Context(), &nokkuv1.PlanGrantRequest{Grant: s})
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
	api := nokkuv1connect.NewTargetAccountServiceClient(clientOn(srv, header("Authorization",
		"Bearer "+seedMember(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR))))
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
		for _, id := range append(slices.Clone(onTag), outside) {
			if err := q.PutGrant(t.Context(), &db.PutGrantParams{
				AccountID: id, SubjectKind: db.SubjectKindTeam, SubjectID: team,
			}); err != nil {
				return err
			}
		}
		return q.PutGrant(t.Context(), &db.PutGrantParams{
			AccountID: onTag[0], SubjectKind: db.SubjectKindUser, SubjectID: person.ID,
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

	planned, err := api.PlanRevoke(t.Context(), &nokkuv1.PlanRevokeRequest{Revoke: spec})
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

	again, err := api.PlanRevoke(t.Context(), &nokkuv1.PlanRevokeRequest{Revoke: spec})
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
