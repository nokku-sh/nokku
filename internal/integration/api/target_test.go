//go:build integration

package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"uuid"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
)

func seedTarget(t *testing.T, cfg *config.Config, workspaceID string) string {
	t.Helper()
	var targetID string
	inWorkspace(t, cfg, workspaceID, func(q *db.Queries) error {
		target, err := q.CreateTarget(t.Context(), &db.CreateTargetParams{
			Name:      uniq("web"),
			Endpoints: []string{"10.0.0.1:22"},
		})
		if err != nil {
			return err
		}
		targetID = target.ID
		return nil
	})
	return targetID
}

func TestSyncTargetUsers(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	targetID := seedTarget(t, cfg, workspaceID)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	hostKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))

	editorAuth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR),
	)
	editor := nokkuv1connect.NewTargetServiceClient(srv.Client(), srv.URL, editorAuth)
	principals := nokkuv1connect.NewTargetAccountServiceClient(srv.Client(), srv.URL, editorAuth)
	_, err = editor.SyncTargetUsers(t.Context(), &nokkuv1.SyncTargetUsersRequest{
		TargetId:      &targetID,
		HostPublicKey: &hostKey,
		Usernames:     []string{"root", "deploy"},
		Endpoints:     []string{"10.0.0.2:22"},
	})
	require.NoError(t, err)

	got, err := editor.GetTarget(t.Context(), &nokkuv1.GetTargetRequest{Id: &targetID})
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.2:22"}, got.GetTarget().GetEndpoints(), "endpoints replaced")
	assert.Equal(t, hostKey, got.GetTarget().GetHostPublicKey(), "host key pinned")
	assert.Contains(t, got.GetTarget().GetMetadata(), "last_manual_sync", "manual sync stamped")

	usernames := func() []string {
		res, err := principals.ListTargetAccounts(t.Context(), &nokkuv1.ListTargetAccountsRequest{
			TargetId: &targetID,
			Limit:    new(int32(100)),
		})
		require.NoError(t, err)
		var out []string
		for _, p := range res.GetAccounts() {
			out = append(out, p.GetUsername())
		}
		return out
	}
	assert.ElementsMatch(t, []string{"root", "deploy"}, usernames())

	// A report without endpoints or key adds users and keeps the rest.
	_, err = editor.SyncTargetUsers(t.Context(), &nokkuv1.SyncTargetUsersRequest{
		TargetId:  &targetID,
		Usernames: []string{"ops"},
	})
	require.NoError(t, err)
	got, err = editor.GetTarget(t.Context(), &nokkuv1.GetTargetRequest{Id: &targetID})
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.2:22"}, got.GetTarget().GetEndpoints(), "endpoints kept")
	assert.Equal(t, hostKey, got.GetTarget().GetHostPublicKey(), "host key kept")
	assert.ElementsMatch(t, []string{"root", "deploy", "ops"}, usernames(), "earlier users are never deleted")

	viewer := nokkuv1connect.NewTargetServiceClient(srv.Client(), srv.URL,
		header("Authorization", "Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER)))
	_, err = viewer.SyncTargetUsers(t.Context(), &nokkuv1.SyncTargetUsersRequest{
		TargetId:  &targetID,
		Usernames: []string{"intruder"},
	})
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "viewer may not sync, got %v", err)
}

func TestUpdateTargetReplacesLists(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	targetID := seedTarget(t, cfg, workspaceID)
	editor := nokkuv1connect.NewTargetServiceClient(srv.Client(), srv.URL,
		header("Authorization", "Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR)))

	updated, err := editor.UpdateTarget(t.Context(), &nokkuv1.UpdateTargetRequest{
		Id:        &targetID,
		Endpoints: []string{"10.0.0.1:22"},
		Tags:      []string{"prod"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"prod"}, updated.GetTarget().GetTags())
	name := updated.GetTarget().GetName()

	updated, err = editor.UpdateTarget(t.Context(), &nokkuv1.UpdateTargetRequest{
		Id:        &targetID,
		Endpoints: []string{"10.0.0.9:22"},
	})
	require.NoError(t, err)
	assert.Empty(t, updated.GetTarget().GetTags(), "an update replaces the tags, the last one can go")
	assert.Equal(t, []string{"10.0.0.9:22"}, updated.GetTarget().GetEndpoints())
	assert.Equal(t, name, updated.GetTarget().GetName(), "unset fields stay as they are")
}

type accessFixture struct {
	workspaceID       string
	alice, bob, carol string
	platform, ci      string
	web1              string
	outsider          string
	client            nokkuv1connect.TargetServiceClient
	memberClient      nokkuv1connect.TargetServiceClient
	// as signs in as one of the seeded users.
	as func(userID string) nokkuv1connect.TargetServiceClient
}

// graphSeed makes web-1 (root: platform, deploy: alice, ci), web-2 (root: platform), db-1 (root: bob) and idle.
type graphSeed struct {
	t       *testing.T
	q       *db.Queries
	targets map[string]string
}

func (s graphSeed) member(name string) string {
	u, err := s.q.CreateUser(s.t.Context(), &db.CreateUserParams{
		Email: uuid.New().String() + "@api.test", Name: name, Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
	})
	require.NoError(s.t, err)
	return u.ID
}

// account creates the target on first use and returns the principal.
func (s graphSeed) account(name string, tags []string, username string) string {
	if s.targets[name] == "" {
		target, err := s.q.CreateTarget(s.t.Context(), &db.CreateTargetParams{Name: name, Tags: tags})
		require.NoError(s.t, err)
		s.targets[name] = target.ID
	}
	if username == "" {
		return ""
	}
	p, err := s.q.CreateTargetAccount(s.t.Context(), &db.CreateTargetAccountParams{
		TargetID: s.targets[name],
		Username: username,
	})
	require.NoError(s.t, err)
	return p.ID
}

func (s graphSeed) grant(principalID, kind, subjectID string) {
	require.NoError(s.t, s.q.AddGrant(s.t.Context(), &db.AddGrantParams{
		AccountID:   principalID,
		SubjectKind: kind,
		SubjectID:   subjectID,
	}))
}

func seedAccessGraph(t *testing.T) accessFixture {
	t.Helper()
	cfg, srv := newTestAPI(t)
	f := accessFixture{workspaceID: seedWorkspace(t, cfg)}
	other := seedOtherWorkspace(t, cfg)

	// The workspace is shared, so earlier tests' grants go first. Only the owner role deletes past RLS.
	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	for _, table := range []string{"targets", "teams", "service_accounts"} {
		_, err = owner.Exec(t.Context(), "DELETE FROM "+table+" WHERE workspace_id = $1", f.workspaceID)
		require.NoError(t, err)
	}
	require.NoError(t, owner.Close(t.Context()))

	inWorkspace(t, cfg, f.workspaceID, func(q *db.Queries) error {
		s := graphSeed{t: t, q: q, targets: map[string]string{}}
		f.alice, f.bob, f.carol = s.member("alice"), s.member("bob"), s.member("carol")
		team, err := q.CreateTeam(t.Context(), &db.CreateTeamParams{Name: "platform"})
		require.NoError(t, err)
		f.platform = team.ID
		for _, userID := range []string{f.alice, f.carol} {
			require.NoError(t, q.AddTeamMember(t.Context(), &db.AddTeamMemberParams{UserID: userID, TeamID: team.ID}))
		}
		f.ci, err = q.CreateServiceAccount(
			t.Context(),
			&db.CreateServiceAccountParams{Name: uniq("ci"), Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER},
		)
		require.NoError(t, err)

		web1Root := s.account("web-1", []string{"prod", "web"}, "root")
		web1Deploy := s.account("web-1", nil, "deploy")
		f.web1 = s.targets["web-1"]
		s.grant(web1Root, db.SubjectKindTeam, f.platform)
		s.grant(web1Deploy, db.SubjectKindUser, f.alice)
		s.grant(web1Deploy, db.SubjectKindServiceAccount, f.ci)
		s.grant(s.account("web-2", []string{"prod"}, "root"), db.SubjectKindTeam, f.platform)
		s.grant(s.account("db-1", nil, "root"), db.SubjectKindUser, f.bob)
		s.account("idle", []string{"prod"}, "")
		return nil
	})
	inWorkspace(t, cfg, other, func(q *db.Queries) error {
		s := graphSeed{t: t, q: q, targets: map[string]string{}}
		f.outsider = s.member("outsider")
		s.grant(s.account("web-1", []string{"prod"}, "root"), db.SubjectKindUser, f.outsider)
		return nil
	})

	client := func(role nokkuv1.WorkspaceRole) nokkuv1connect.TargetServiceClient {
		return nokkuv1connect.NewTargetServiceClient(srv.Client(), srv.URL,
			header("Authorization", "Bearer "+seedMember(t, cfg, f.workspaceID, role)))
	}
	f.client, f.memberClient = client(
		nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER,
	), client(
		nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
	)
	f.as = func(userID string) nokkuv1connect.TargetServiceClient {
		token := sessionFor(t, cfg, &db.User{ID: userID})
		return nokkuv1connect.NewTargetServiceClient(srv.Client(), srv.URL, header("Authorization", "Bearer "+token))
	}
	return f
}

func TestGetSubjectAccess(t *testing.T) {
	f := seedAccessGraph(t)

	// access returns the accounts per target name and the principal count.
	access := func(client nokkuv1connect.TargetServiceClient, subjectID string) (map[string][]string, int) {
		res, err := client.GetSubjectAccess(t.Context(), &nokkuv1.GetSubjectAccessRequest{
			SubjectId: &subjectID,
		})
		require.NoError(t, err)
		accounts, principals := map[string][]string{}, 0
		for _, target := range res.GetTargets() {
			accounts[target.GetName()] = target.GetUsernames()
			principals += len(target.GetAccounts())
		}
		return accounts, principals
	}

	got, principals := access(f.as(f.carol), f.carol)
	assert.Equal(t, map[string][]string{"web-1": {"root"}, "web-2": {"root"}}, got,
		"a member reads its own access, deploy on web-1 is not carol's")
	assert.Zero(t, principals, "the grants of others are for viewers")

	got, _ = access(f.as(f.alice), f.alice)
	assert.Equal(t, map[string][]string{"web-1": {"deploy", "root"}, "web-2": {"root"}}, got,
		"direct and team grants")

	_, err := f.as(f.carol).GetSubjectAccess(t.Context(), &nokkuv1.GetSubjectAccessRequest{
		SubjectId: &f.bob,
	})
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err),
		"a member may not read another subject, got %v", err)

	got, principals = access(f.client, f.carol)
	assert.Equal(t, map[string][]string{"web-1": {"root"}, "web-2": {"root"}}, got)
	assert.Equal(t, 3, principals, "a viewer gets every account on those targets")
}

func TestTargetsCarryPrincipals(t *testing.T) {
	f := seedAccessGraph(t)

	list, err := f.client.ListTargets(t.Context(), &nokkuv1.ListTargetsRequest{
		Limit: new(int32(50)),
	})
	require.NoError(t, err)
	accounts := map[string][]string{}
	for _, target := range list.GetTargets() {
		for _, p := range target.GetAccounts() {
			accounts[target.GetName()] = append(accounts[target.GetName()], p.GetUsername())
		}
	}
	assert.Equal(t,
		map[string][]string{"web-1": {"deploy", "root"}, "web-2": {"root"}, "db-1": {"root"}},
		accounts, "every account by username, idle has none, the other workspace stays out")

	got, err := f.client.GetTarget(t.Context(), &nokkuv1.GetTargetRequest{
		Id: &f.web1,
	})
	require.NoError(t, err)
	principals := got.GetTarget().GetAccounts()
	require.Len(t, principals, 2, "web-1 has deploy and root")
	assert.Equal(t, "deploy", principals[0].GetUsername())
	assert.Equal(t, []string{f.alice}, principals[0].GetUserIds())
	assert.Equal(t, []string{f.ci}, principals[0].GetServiceAccountIds())
	assert.Equal(t, "root", principals[1].GetUsername())
	assert.Equal(t, []string{f.platform}, principals[1].GetTeamIds())
}

func TestGetAccessGraph(t *testing.T) {
	f := seedAccessGraph(t)

	graph := func(filter *nokkuv1.AccessGraphFilter) *nokkuv1.GetAccessGraphResponse {
		res, err := f.client.GetAccessGraph(t.Context(), &nokkuv1.GetAccessGraphRequest{
			Filter: filter,
		})
		require.NoError(t, err)
		return res
	}
	held := func(res *nokkuv1.GetAccessGraphResponse) map[string]int32 {
		out := map[string]int32{}
		for _, s := range res.GetSubjects() {
			out[s.GetId()] = s.GetTargets()
		}
		return out
	}
	accounts := func(res *nokkuv1.GetAccessGraphResponse) map[string]int32 {
		out := map[string]int32{}
		for _, a := range res.GetAccounts() {
			out[a.GetUsername()] = a.GetTargets()
		}
		return out
	}
	// tags maps a tag to {matched, total}.
	tags := func(res *nokkuv1.GetAccessGraphResponse) map[string][2]int32 {
		out := map[string][2]int32{}
		for _, tag := range res.GetTags() {
			out[tag.GetTag()] = [2]int32{tag.GetTargets(), tag.GetTotal()}
		}
		return out
	}
	grants := func(res *nokkuv1.GetAccessGraphResponse) map[string]int32 {
		out := map[string]int32{}
		for _, g := range res.GetGrants() {
			out[g.GetSubjectId()+" "+g.GetUsername()] = g.GetTargets()
		}
		return out
	}
	reach := func(res *nokkuv1.GetAccessGraphResponse) map[string]int32 {
		out := map[string]int32{}
		for _, r := range res.GetReach() {
			out[r.GetUsername()+" "+r.GetTag()] = r.GetTargets()
		}
		return out
	}

	all := graph(nil)
	assert.EqualValues(t, 3, all.GetTargets(), "idle has no grant and the other workspace is out of scope")
	assert.Equal(t, map[string]int32{f.platform: 2, f.alice: 1, f.bob: 1, f.ci: 1}, held(all))
	assert.Equal(t, map[string]int32{"root": 3, "deploy": 1}, accounts(all))
	assert.Equal(t, map[string][2]int32{"prod": {2, 3}, "web": {1, 1}, "": {1, 1}}, tags(all))
	assert.Equal(t, map[string]int32{
		f.platform + " root": 2,
		f.alice + " deploy":  1,
		f.bob + " root":      1,
		f.ci + " deploy":     1,
	}, grants(all))
	assert.Equal(t, map[string]int32{
		"root prod": 2, "root web": 1, "root ": 1,
		"deploy prod": 1, "deploy web": 1,
	}, reach(all))
	for _, s := range all.GetSubjects() {
		if s.GetId() == f.platform {
			assert.Equal(t, nokkuv1.SubjectKind_SUBJECT_KIND_TEAM, s.GetKind())
			assert.Equal(t, "platform", s.GetName())
			assert.EqualValues(t, 2, s.GetMemberCount())
		}
	}

	// alice reaches web-1 twice over, once herself and once through platform.
	alice := graph(&nokkuv1.AccessGraphFilter{SubjectId: &f.alice})
	assert.EqualValues(t, 2, alice.GetTargets())
	assert.Equal(t, map[string]int32{f.platform: 2, f.alice: 1}, held(alice))
	assert.Equal(t, map[string]int32{"root": 2, "deploy": 1}, accounts(alice))
	assert.Equal(t, map[string][2]int32{"prod": {2, 3}, "web": {1, 1}, "": {0, 1}}, tags(alice))

	carol := graph(&nokkuv1.AccessGraphFilter{SubjectId: &f.carol})
	assert.EqualValues(t, 2, carol.GetTargets(), "team access counts")
	assert.Equal(t, map[string]int32{f.platform: 2, f.carol: 0}, held(carol), "carol is named though she holds nothing")

	untagged := graph(&nokkuv1.AccessGraphFilter{Tag: new("")})
	assert.EqualValues(t, 1, untagged.GetTargets())
	assert.Equal(t, map[string]int32{f.bob: 1}, held(untagged))
	assert.Equal(t, map[string]int32{"root ": 1}, reach(untagged))

	prod := graph(&nokkuv1.AccessGraphFilter{Tag: new("prod")})
	assert.Equal(t, map[string][2]int32{"prod": {2, 3}, "web": {0, 1}, "": {0, 1}}, tags(prod),
		"web-1 is also tagged web, a tag filter only lights its own tag")

	web1 := graph(&nokkuv1.AccessGraphFilter{TargetId: &f.web1})
	assert.Equal(t, map[string]int32{f.platform: 1, f.alice: 1, f.ci: 1}, held(web1))
	assert.Equal(t, map[string]int32{"root": 1, "deploy": 1}, accounts(web1))

	deploy := graph(&nokkuv1.AccessGraphFilter{Username: new("deploy")})
	assert.Equal(t, map[string]int32{f.alice: 1, f.ci: 1}, held(deploy))

	outsider := graph(&nokkuv1.AccessGraphFilter{SubjectId: &f.outsider})
	assert.Zero(t, outsider.GetTargets())
	assert.Empty(t, outsider.GetSubjects(), "a subject of another workspace is not even named")

	_, err := f.memberClient.GetAccessGraph(t.Context(), &nokkuv1.GetAccessGraphRequest{})
	assert.Equal(
		t,
		connect.CodePermissionDenied,
		connect.CodeOf(err),
		"a plain member may not read the graph, got %v",
		err,
	)
}

func TestListAccessGraphTargets(t *testing.T) {
	f := seedAccessGraph(t)

	// list returns "name" for a matched target and "-name" for the rest.
	list := func(tag string, filter *nokkuv1.AccessGraphFilter, limit int32) ([]string, int32) {
		res, err := f.client.ListAccessGraphTargets(t.Context(), &nokkuv1.ListAccessGraphTargetsRequest{
			Filter: filter,
			Tag:    &tag,
			Limit:  &limit,
		})
		require.NoError(t, err)
		var out []string
		for _, target := range res.GetTargets() {
			name := target.GetName()
			if !target.GetMatched() {
				name = "-" + name
			}
			out = append(out, name)
		}
		return out, res.GetTotal()
	}

	got, total := list("prod", nil, 100)
	assert.Equal(t, []string{"web-1", "web-2", "-idle"}, got, "granted targets first, then by name")
	assert.EqualValues(t, 3, total)

	got, total = list("prod", nil, 2)
	assert.Equal(t, []string{"web-1", "web-2"}, got)
	assert.EqualValues(t, 3, total, "total ignores the page")

	got, _ = list("prod", &nokkuv1.AccessGraphFilter{SubjectId: &f.carol}, 100)
	assert.Equal(t, []string{"web-1", "web-2", "-idle"}, got, "team access counts")

	got, _ = list("prod", &nokkuv1.AccessGraphFilter{SubjectId: &f.bob}, 100)
	assert.Equal(t, []string{"-idle", "-web-1", "-web-2"}, got)

	got, _ = list("prod", &nokkuv1.AccessGraphFilter{Username: new("deploy")}, 100)
	assert.Equal(t, []string{"web-1", "-idle", "-web-2"}, got)

	got, _ = list("prod", &nokkuv1.AccessGraphFilter{TargetId: &f.web1}, 100)
	assert.Equal(t, []string{"web-1", "-idle", "-web-2"}, got)

	got, _ = list("", nil, 100)
	assert.Equal(t, []string{"db-1"}, got, "an empty tag lists the untagged targets")

	got, _ = list("", &nokkuv1.AccessGraphFilter{Tag: new("prod")}, 100)
	assert.Equal(t, []string{"-db-1"}, got, "a tag filter only matches its own tag")
}

// A server made by hand starts with the root account, no host reports one.
func TestNewServerHasTheRootAccount(t *testing.T) {
	cfg, srv := newTestAPI(t)
	admin := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	targets := nokkuv1connect.NewTargetServiceClient(srv.Client(), srv.URL, admin)
	created, err := targets.CreateTarget(t.Context(), &nokkuv1.CreateTargetRequest{Name: new(uniq("web"))})
	require.NoError(t, err)

	got, err := targets.GetTarget(t.Context(), &nokkuv1.GetTargetRequest{Id: new(created.GetTarget().GetId())})
	require.NoError(t, err)
	var accounts []string
	for _, p := range got.GetTarget().GetAccounts() {
		accounts = append(accounts, p.GetUsername())
	}
	assert.Equal(t, []string{"root"}, accounts)
}
