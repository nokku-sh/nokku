//go:build integration

package api_test

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/app"
	"github.com/nokku-sh/nokku/core/internal/db"
)

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

// graphSeed makes web-1 (root: platform, deploy: alice, ci), web-2 (root:
// platform), db-1 (root: bob) and idle.
type graphSeed struct {
	t       *testing.T
	q       *db.Queries
	targets map[string]string
}

func seedTarget(t *testing.T, cfg *app.Config, workspaceID string) string {
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

// nkTargets is the target client of a new nk session of u.
func nkTargets(
	t *testing.T,
	cfg *app.Config,
	srv *httptest.Server,
	u *db.User,
) nokkuv1connect.TargetServiceClient {
	t.Helper()
	return nokkuv1connect.NewTargetServiceClient(partialConn(srv, cliSessionFor(t, cfg, u, partialHostKey(t))))
}

// webTargets is the target client of a new browser session of u, signed in age ago.
func webTargets(
	t *testing.T,
	cfg *app.Config,
	srv *httptest.Server,
	u *db.User,
	age time.Duration,
) nokkuv1connect.TargetServiceClient {
	t.Helper()
	return nokkuv1connect.NewTargetServiceClient(clientOn(srv, signedIn(t, cfg, browserSession(t, cfg, u, age))))
}

func denied(t *testing.T, err error, what string) {
	t.Helper()
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "%s, got %v", what, err)
}

func TestSyncTargetUsers(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	hostKey := partialHostKey(t)

	// The web app reads, nk reports.
	editorUser := seedUser(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR)
	editorAuth := header("Authorization", "Bearer "+sessionFor(t, cfg, editorUser))
	editor := nokkuv1connect.NewTargetServiceClient(
		clientOn(srv, editorAuth),
	)
	nk := nkTargets(t, cfg, srv, editorUser)
	added, err := nk.CreateTarget(t.Context(), &nokkuv1.CreateTargetRequest{
		Name: new(uniq("web")), Endpoints: []string{"10.0.0.1:22"},
	})
	require.NoError(t, err)
	targetID := added.GetTarget().GetId()
	accounts := nokkuv1connect.NewTargetAccountServiceClient(
		clientOn(srv, editorAuth),
	)
	authority, err := nokkuv1connect.NewCertificateServiceClient(clientOn(srv, editorAuth)).
		GetCertificateAuthority(t.Context(), &nokkuv1.GetCertificateAuthorityRequest{})
	require.NoError(t, err)
	caKey := authority.GetCertificateAuthority().GetUserPublicKey()

	// A host written with a key a rollover replaced is not in sync.
	_, err = nk.SyncTargetUsers(t.Context(), &nokkuv1.SyncTargetUsersRequest{
		TargetId:        &targetID,
		Usernames:       []string{"root"},
		UserCaPublicKey: &hostKey,
	})
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err), "a stale CA key was reported, got %v", err)
	stale, err := editor.GetTarget(t.Context(), &nokkuv1.GetTargetRequest{Id: &targetID})
	require.NoError(t, err)
	assert.Nil(t, stale.GetTarget().GetLastSyncAt(), "a refused report stamped the sync")

	_, err = nk.SyncTargetUsers(t.Context(), &nokkuv1.SyncTargetUsersRequest{
		TargetId:        &targetID,
		HostPublicKey:   &hostKey,
		Usernames:       []string{"root", "deploy"},
		UserCaPublicKey: &caKey,
	})
	require.NoError(t, err)

	got, err := editor.GetTarget(t.Context(), &nokkuv1.GetTargetRequest{Id: &targetID})
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.1:22"}, got.GetTarget().GetEndpoints(), "a report moved the server")
	assert.Equal(t, hostKey, got.GetTarget().GetHostPublicKey(), "host key pinned")
	assert.NotNil(t, got.GetTarget().GetLastSyncAt(), "manual sync stamped")

	usernames := func() []string {
		res, err := accounts.ListTargetAccounts(t.Context(), &nokkuv1.ListTargetAccountsRequest{
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
	_, err = nk.SyncTargetUsers(t.Context(), &nokkuv1.SyncTargetUsersRequest{
		TargetId:        &targetID,
		Usernames:       []string{"ops"},
		UserCaPublicKey: &caKey,
	})
	require.NoError(t, err)
	got, err = editor.GetTarget(t.Context(), &nokkuv1.GetTargetRequest{Id: &targetID})
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.1:22"}, got.GetTarget().GetEndpoints(), "endpoints kept")
	assert.Equal(t, hostKey, got.GetTarget().GetHostPublicKey(), "host key kept")
	assert.ElementsMatch(t, []string{"root", "deploy", "ops"}, usernames(), "earlier users are never deleted")

	// A host can name a login twice, and one odd name must not cost the others.
	_, err = nk.SyncTargetUsers(t.Context(), &nokkuv1.SyncTargetUsersRequest{
		TargetId:        &targetID,
		Usernames:       []string{"backup", "ops", "backup", "not a login"},
		UserCaPublicKey: &caKey,
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"root", "deploy", "ops", "backup"}, usernames())

	viewerUser := seedUser(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER)
	viewer := nkTargets(t, cfg, srv, viewerUser)
	_, err = viewer.SyncTargetUsers(t.Context(), &nokkuv1.SyncTargetUsersRequest{
		TargetId:        &targetID,
		Usernames:       []string{"intruder"},
		UserCaPublicKey: &caKey,
	})
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "viewer may not sync, got %v", err)
}

// Everyone's ssh trusts the pinned host key, so a report replaces it only for whoever added the server.
func TestOnlyWhoAddedAServerRepinsIt(t *testing.T) {
	cfg, srv := newTestAPI(t)
	ws := testWorkspace.ID
	alice := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR)
	bob := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)
	aliceNK, bobNK := nkTargets(t, cfg, srv, alice), nkTargets(t, cfg, srv, bob)
	aliceWeb, bobWeb := webTargets(t, cfg, srv, alice, 0), webTargets(t, cfg, srv, bob, 0)
	caKey := workspaceCA(t, cfg).GetUserPublicKey()

	pinned, attacker := partialHostKey(t), partialHostKey(t)
	address := []string{"10.0.0.2:22"}
	added, err := aliceNK.CreateTarget(t.Context(), &nokkuv1.CreateTargetRequest{
		Name: new(uniq("web")), Endpoints: address, HostPublicKey: &pinned,
	})
	require.NoError(t, err)
	id := added.GetTarget().GetId()

	report := func(as nokkuv1connect.TargetServiceClient, id, key string) error {
		_, err := as.SyncTargetUsers(t.Context(), &nokkuv1.SyncTargetUsersRequest{
			TargetId: &id, Usernames: []string{"root"}, HostPublicKey: &key, UserCaPublicKey: &caKey,
		})
		return err
	}
	stored := func(id string) *nokkuv1.Target {
		t.Helper()
		got, err := bobWeb.GetTarget(t.Context(), &nokkuv1.GetTargetRequest{Id: &id})
		require.NoError(t, err)
		return got.GetTarget()
	}

	denied(t, report(webTargets(t, cfg, srv, alice, oldSignIn), id, attacker), "an old cookie pinned a host key")
	denied(t, report(aliceWeb, id, attacker), "a cookie reported a host, only nk does")
	denied(t, report(bobNK, id, attacker), "nk replaced the host key of a server someone else added")
	got := stored(id)
	assert.Equal(t, pinned, got.GetHostPublicKey(), "a refused report changed the pinned host key")
	assert.Nil(t, got.GetLastSyncAt(), "a refused report stamped the sync")
	assert.Equal(t, alice.ID, got.GetCreatedBy(), "nk can't tell who added the server")

	// After a CA rollover anyone syncs every server again, with the key it has.
	require.NoError(t, report(bobNK, id, pinned), "an unchanged report of someone else's server was refused")
	assert.NotNil(t, stored(id).GetLastSyncAt(), "the sync was not stamped")

	// A server added in the web app has no key yet, its first sync pins one.
	blank, err := aliceWeb.CreateTarget(t.Context(), &nokkuv1.CreateTargetRequest{Name: new(uniq("web"))})
	require.NoError(t, err)
	blankID := blank.GetTarget().GetId()
	require.NoError(t, report(bobNK, blankID, pinned), "the first sync of a server from the web app was refused")
	assert.Equal(t, pinned, stored(blankID).GetHostPublicKey(), "the first sync pinned no host key")
	denied(t, report(bobNK, blankID, attacker), "nk replaced a key it had just pinned on someone else's server")

	// Reinstalled, and alice is away: a fresh sign-in forgets the pin and the next sync is a first one again.
	_, err = bobWeb.ForgetHostKey(t.Context(), &nokkuv1.ForgetHostKeyRequest{Id: &id})
	require.NoError(t, err)
	assert.Empty(t, stored(id).GetHostPublicKey(), "the pin was not forgotten")
	reinstalled := partialHostKey(t)
	require.NoError(t, report(bobNK, id, reinstalled), "the sync after a forgotten key was refused")
	assert.Equal(t, reinstalled, stored(id).GetHostPublicKey())

	// A daemon reports for its own server, and the CA vouches for that host.
	_, enrolled := enrollTestDaemon(t, cfg, srv, ws, true)
	err = report(bobNK, enrolled.GetTargetId(), pinned)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "nk reported for a daemon's server, got %v", err)

	require.NoError(t, report(aliceNK, id, attacker), "whoever added a server could not pin its new key")
	got = stored(id)
	assert.Equal(t, attacker, got.GetHostPublicKey())
	assert.Equal(t, address, got.GetEndpoints(), "a report moved the server")
}

// People type a server's name, so an old cookie or a colleague's nk must not free it for another host.
func TestAServerIsNotSwappedByDeletingIt(t *testing.T) {
	cfg, srv := newTestAPI(t)
	ws := testWorkspace.ID
	alice := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR)
	bob := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR)
	aliceNK, bobNK := nkTargets(t, cfg, srv, alice), nkTargets(t, cfg, srv, bob)
	bobWeb := webTargets(t, cfg, srv, bob, 0)
	add := func(as nokkuv1connect.TargetServiceClient, req *nokkuv1.CreateTargetRequest) (string, error) {
		req.Name = new(uniq("web"))
		res, err := as.CreateTarget(t.Context(), req)
		return res.GetTarget().GetId(), err
	}
	remove := func(as nokkuv1connect.TargetServiceClient, id string) error {
		_, err := as.DeleteTarget(t.Context(), &nokkuv1.DeleteTargetRequest{Id: &id})
		return err
	}
	pinned := partialHostKey(t)
	synced := func() string {
		t.Helper()
		id, err := add(
			aliceNK,
			&nokkuv1.CreateTargetRequest{Endpoints: []string{"10.0.0.2:22"}, HostPublicKey: &pinned},
		)
		require.NoError(t, err)
		return id
	}
	first, second := synced(), synced()

	denied(t, remove(bobNK, first), "nk deleted a server someone else added")
	// A refused fresh check ends the old session, so each old cookie is its own.
	err := remove(webTargets(t, cfg, srv, bob, oldSignIn), first)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "an old cookie deleted a server, got %v", err)
	_, err = bobWeb.GetTarget(t.Context(), &nokkuv1.GetTargetRequest{Id: &first})
	require.NoError(t, err, "a refused delete removed the server")

	// A rename frees the name just like a delete.
	_, err = webTargets(t, cfg, srv, bob, oldSignIn).UpdateTarget(t.Context(), masked(
		&nokkuv1.UpdateTargetRequest{Id: &first, Name: new(uniq("moved"))},
	))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "an old cookie renamed a server, got %v", err)

	_, err = add(bobWeb, &nokkuv1.CreateTargetRequest{Endpoints: []string{"203.0.113.66:22"}})
	denied(t, err, "a cookie added a server with an address")
	_, err = add(bobWeb, &nokkuv1.CreateTargetRequest{HostPublicKey: new(partialHostKey(t))})
	denied(t, err, "a cookie added a server with a host key")
	byName, err := add(webTargets(t, cfg, srv, bob, oldSignIn), &nokkuv1.CreateTargetRequest{})
	require.NoError(t, err, "the web app could not add a server by name")

	// A handoff needs nobody who added the server, only a fresh sign-in.
	require.NoError(t, remove(bobWeb, first), "a fresh sign-in could not delete a colleague's server")
	require.NoError(t, remove(aliceNK, second), "nk could not delete the server its person added")
	require.NoError(t, remove(bobNK, byName), "nk could not delete a server its person added in the web app")
}

// Sessions and recordings show the daemon's name, so a rename has to reach it.
func TestRenameReachesTheDaemon(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	_, first := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	_, second := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	editor := nokkuv1connect.NewTargetServiceClient(clientOn(srv, header(
		"Authorization", "Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)))
	daemonName := func(id string) string {
		var name string
		require.NoError(t, cfg.Conn.TenantTx(wsCtx(t), func(q *db.Queries) error {
			d, err := q.GetDaemon(t.Context(), id)
			if err != nil {
				return err
			}
			name = d.Name
			return nil
		}))
		return name
	}

	name := uniq("renamed")
	_, err := editor.UpdateTarget(t.Context(), masked(&nokkuv1.UpdateTargetRequest{
		Id: new(first.GetTargetId()), Name: &name,
	}))
	require.NoError(t, err)
	assert.Equal(t, name, daemonName(first.GetId()))

	before := daemonName(second.GetId())
	_, err = editor.UpdateTarget(t.Context(), masked(&nokkuv1.UpdateTargetRequest{
		Id: new(second.GetTargetId()), Description: new("no name in this update"),
	}))
	require.NoError(t, err)
	assert.Equal(t, before, daemonName(second.GetId()), "an update without a name renamed the daemon")

	_, err = editor.UpdateTarget(t.Context(), masked(&nokkuv1.UpdateTargetRequest{
		Id: new(second.GetTargetId()), Name: &name,
	}))
	require.Error(t, err, "two daemons got one name")
	assert.Equal(t, before, daemonName(second.GetId()), "a refused rename still reached the daemon")
}

func TestUpdateTargetListsChangeOnlyWhenNamed(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	targetID := seedTarget(t, cfg, workspaceID)
	editor := nokkuv1connect.NewTargetServiceClient(
		clientOn(
			srv,
			header(
				"Authorization",
				"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR),
			),
		),
	)

	updated, err := editor.UpdateTarget(t.Context(), masked(&nokkuv1.UpdateTargetRequest{
		Id:        &targetID,
		Endpoints: []string{"10.0.0.1:22"},
		Tags:      []string{"prod"},
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"prod"}, updated.GetTarget().GetTags())
	name := updated.GetTarget().GetName()

	updated, err = editor.UpdateTarget(t.Context(), masked(&nokkuv1.UpdateTargetRequest{
		Id:        &targetID,
		Endpoints: []string{"10.0.0.9:22"},
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"prod"}, updated.GetTarget().GetTags(), "a list the update leaves out stays")
	assert.Equal(t, []string{"10.0.0.9:22"}, updated.GetTarget().GetEndpoints())
	assert.Equal(t, name, updated.GetTarget().GetName(), "unset fields stay as they are")

	updated, err = editor.UpdateTarget(t.Context(), &nokkuv1.UpdateTargetRequest{
		Id:         &targetID,
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"tags"}},
	})
	require.NoError(t, err)
	assert.Empty(t, updated.GetTarget().GetTags(), "naming a list with nothing in it clears it")
	assert.Equal(t, []string{"10.0.0.9:22"}, updated.GetTarget().GetEndpoints())

	_, err = editor.UpdateTarget(t.Context(), &nokkuv1.UpdateTargetRequest{
		Id:         &targetID,
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"host_public_key"}},
	})
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "only nk sync on the server pins a host key")
}

func (s graphSeed) member(name string) string {
	u, err := s.q.CreateUser(s.t.Context(), &db.CreateUserParams{
		Email: uuid.New().String() + "@api.test", Name: name, Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
	})
	require.NoError(s.t, err)
	return u.ID
}

// account creates the target on first use and returns the account.
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

func (s graphSeed) grant(accountID, kind, subjectID string) {
	require.NoError(s.t, s.q.PutGrant(s.t.Context(), &db.PutGrantParams{
		AccountID:   accountID,
		SubjectKind: kind,
		SubjectID:   subjectID,
	}))
}

func seedAccessGraph(t *testing.T) accessFixture {
	t.Helper()
	cfg, srv := newTestAPI(t)
	f := accessFixture{workspaceID: testWorkspace.ID}
	other := seedOtherWorkspace(t, cfg)

	// Earlier tests' grants go first, a daemon with its target as the API does. Only the owner gets past RLS.
	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	for _, table := range []string{"daemons", "targets", "teams", "service_accounts"} {
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
		return nokkuv1connect.NewTargetServiceClient(
			clientOn(srv, header("Authorization", "Bearer "+seedMember(t, cfg, f.workspaceID, role))),
		)
	}
	f.client, f.memberClient = client(
		nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER,
	), client(
		nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
	)
	f.as = func(userID string) nokkuv1connect.TargetServiceClient {
		token := sessionFor(t, cfg, &db.User{ID: userID, Active: true})
		return nokkuv1connect.NewTargetServiceClient(
			clientOn(srv, header("Authorization", "Bearer "+token)),
		)
	}
	return f
}

func TestGetSubjectAccess(t *testing.T) {
	f := seedAccessGraph(t)

	// access returns the usernames per target and the count of all accounts.
	access := func(client nokkuv1connect.TargetServiceClient, subjectID string) (map[string][]string, int) {
		res, err := client.GetSubjectAccess(t.Context(), &nokkuv1.GetSubjectAccessRequest{
			SubjectId: &subjectID,
		})
		require.NoError(t, err)
		usernames, accounts := map[string][]string{}, 0
		for _, target := range res.GetTargets() {
			usernames[target.GetName()] = target.GetUsernames()
			accounts += len(target.GetAccounts())
		}
		return usernames, accounts
	}

	got, accounts := access(f.as(f.carol), f.carol)
	assert.Equal(t, map[string][]string{"web-1": {"root"}, "web-2": {"root"}}, got,
		"a member reads its own access, deploy on web-1 is not carol's")
	assert.Zero(t, accounts, "the grants of others are for viewers")

	got, _ = access(f.as(f.alice), f.alice)
	assert.Equal(t, map[string][]string{"web-1": {"deploy", "root"}, "web-2": {"root"}}, got,
		"direct and team grants")

	_, err := f.as(f.carol).GetSubjectAccess(t.Context(), &nokkuv1.GetSubjectAccessRequest{
		SubjectId: &f.bob,
	})
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err),
		"a member may not read another subject, got %v", err)

	got, accounts = access(f.client, f.carol)
	assert.Equal(t, map[string][]string{"web-1": {"root"}, "web-2": {"root"}}, got)
	assert.Equal(t, 3, accounts, "a viewer gets every account on those targets")
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
	web1Accounts := got.GetTarget().GetAccounts()
	require.Len(t, web1Accounts, 2, "web-1 has deploy and root")
	assert.Equal(t, "deploy", web1Accounts[0].GetUsername())
	assert.Equal(t, []string{f.alice}, web1Accounts[0].GetUserIds())
	assert.Equal(t, []string{f.ci}, web1Accounts[0].GetServiceAccountIds())
	assert.Equal(t, "root", web1Accounts[1].GetUsername())
	assert.Equal(t, []string{f.platform}, web1Accounts[1].GetTeamIds())
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

// A table on a last page that just emptied still needs the total to page back.
func TestAPagePastTheEndKeepsTheTotal(t *testing.T) {
	f := seedAccessGraph(t)
	past := new(int32(100))

	all, err := f.client.ListTargets(t.Context(), &nokkuv1.ListTargetsRequest{Limit: new(int32(10))})
	require.NoError(t, err)
	require.Positive(t, all.GetTotal())

	targets, err := f.client.ListTargets(t.Context(), &nokkuv1.ListTargetsRequest{
		Limit:  new(int32(10)),
		Offset: past,
	})
	require.NoError(t, err)
	assert.Empty(t, targets.GetTargets())
	assert.Equal(t, all.GetTotal(), targets.GetTotal())

	graph, err := f.client.ListAccessGraphTargets(t.Context(), &nokkuv1.ListAccessGraphTargetsRequest{
		Tag:    new("prod"),
		Limit:  new(int32(10)),
		Offset: past,
	})
	require.NoError(t, err)
	assert.Empty(t, graph.GetTargets())
	assert.EqualValues(t, 3, graph.GetTotal())
}

// A server made by hand starts with the root account, no host reports one.
func TestNewServerHasTheRootAccount(t *testing.T) {
	cfg, srv := newTestAPI(t)
	admin := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	targets := nokkuv1connect.NewTargetServiceClient(
		clientOn(srv, admin),
	)
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

// A hand-made server can start with grants, the first sync lets people in.
func TestNewServerSeedsGrants(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	member := seedUser(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	editor := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR),
	)
	targets := nokkuv1connect.NewTargetServiceClient(
		clientOn(srv, editor),
	)

	created, err := targets.CreateTarget(t.Context(), &nokkuv1.CreateTargetRequest{
		Name: new(uniq("web")),
		Grants: []*nokkuv1.JoinTokenGrant{
			{Username: new("root"), UserIds: []string{member.ID}},
			{Username: new("deploy"), UserIds: []string{member.ID}},
		},
	})
	require.NoError(t, err)

	got, err := targets.GetTarget(t.Context(), &nokkuv1.GetTargetRequest{Id: new(created.GetTarget().GetId())})
	require.NoError(t, err)
	granted := map[string][]string{}
	for _, a := range got.GetTarget().GetAccounts() {
		granted[a.GetUsername()] = a.GetUserIds()
	}
	assert.Equal(t, map[string][]string{"root": {member.ID}, "deploy": {member.ID}}, granted)

	name := uniq("db")
	_, err = targets.CreateTarget(t.Context(), &nokkuv1.CreateTargetRequest{
		Name:   new(name),
		Grants: []*nokkuv1.JoinTokenGrant{{Username: new("root"), TeamIds: []string{member.ID}}},
	})
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "a user id is not a team, got %v", err)

	listed, err := targets.ListTargets(t.Context(), &nokkuv1.ListTargetsRequest{Query: new(name)})
	require.NoError(t, err)
	assert.Empty(t, listed.GetTargets(), "a refused grant leaves no target behind")
}

// Deleting a server takes its daemon along, no daemon stays without a server.
func TestDeleteTargetTakesItsDaemon(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	admin := clientOn(srv, header("Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)))
	_, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)

	_, err := nokkuv1connect.NewTargetServiceClient(admin).DeleteTarget(t.Context(),
		&nokkuv1.DeleteTargetRequest{Id: enrolled.TargetId})
	require.NoError(t, err)
	_, err = nokkuv1connect.NewDaemonServiceClient(admin).GetDaemon(t.Context(),
		&nokkuv1.GetDaemonRequest{Id: enrolled.Id})
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "the daemon was left behind")
}

// carol only gets in through platform, so she has no row and her use of web-2 counts for the team.
func TestGetAccessMatrix(t *testing.T) {
	f := seedAccessGraph(t)
	cfg, _ := newTestAPI(t)
	inWorkspace(t, cfg, f.workspaceID, func(q *db.Queries) error {
		var web2 string
		targets, err := q.ListTargets(t.Context(), &db.ListTargetsParams{Query: new("web-2")})
		if err != nil {
			return err
		}
		web2 = targets[0].Target.ID
		return q.TouchAccessUsage(t.Context(), &db.TouchAccessUsageParams{TargetID: web2, SubjectID: f.carol})
	})

	matrix := func(req *nokkuv1.GetAccessMatrixRequest) *nokkuv1.GetAccessMatrixResponse {
		res, err := f.client.GetAccessMatrix(t.Context(), req)
		require.NoError(t, err)
		return res
	}
	type cell struct {
		targets   int32
		usernames string
	}
	cells := func(r *nokkuv1.AccessMatrixRow) map[string]cell {
		out := map[string]cell{}
		for _, c := range r.GetCells() {
			out[c.GetTag()] = cell{c.GetTargets(), strings.Join(c.GetUsernames(), ",")}
		}
		return out
	}

	res := matrix(&nokkuv1.GetAccessMatrixRequest{})
	var columns []string
	for _, c := range res.GetColumns() {
		columns = append(columns, c.GetTag())
	}
	assert.Equal(t, []string{"prod", "", "web"}, columns, "the biggest tags first, untagged is the empty one")
	assert.EqualValues(t, 3, res.GetColumns()[0].GetTotal())

	require.EqualValues(t, 4, res.GetTotal())
	var names []string
	for _, r := range res.GetRows() {
		names = append(names, r.GetName())
	}
	assert.Equal(t, "platform", names[0], "teams come first")
	assert.NotContains(t, names, "carol", "someone in a team has no row without a grant of her own")

	platform := res.GetRows()[0]
	assert.EqualValues(t, 2, platform.GetMemberCount())
	assert.Equal(t, map[string]cell{"prod": {2, "root"}, "web": {1, "root"}}, cells(platform),
		"only the cells with access")
	assert.NotNil(t, platform.GetCells()[0].GetLastUsedAt(), "a member's use is the team's")
	assert.Nil(t, platform.GetCells()[0].GetExpiresAt(), "for good")

	teams := matrix(&nokkuv1.GetAccessMatrixRequest{Kind: nokkuv1.SubjectKind_SUBJECT_KIND_TEAM.Enum()})
	assert.Len(t, teams.GetRows(), 1)
	bob := matrix(&nokkuv1.GetAccessMatrixRequest{Query: new("bob"), Tags: []string{"", "prod"}})
	require.Len(t, bob.GetRows(), 1)
	assert.Equal(t, map[string]cell{"": {1, "root"}}, cells(bob.GetRows()[0]))

	page := matrix(&nokkuv1.GetAccessMatrixRequest{Limit: new(int32(2)), Offset: new(int32(2))})
	assert.Len(t, page.GetRows(), 2)
	assert.EqualValues(t, 4, page.GetTotal(), "the total counts every row")

	_, err := f.memberClient.GetAccessMatrix(t.Context(), &nokkuv1.GetAccessMatrixRequest{})
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "a member reads only its own access")

	inWorkspace(t, cfg, f.workspaceID, func(q *db.Queries) error {
		return q.SetUserActive(t.Context(), &db.SetUserActiveParams{ID: f.bob, Active: false})
	})
	assert.Empty(t, matrix(&nokkuv1.GetAccessMatrixRequest{Query: new("bob")}).GetRows(),
		"someone deactivated logs in nowhere")
}

// A service account key sits in a secret store. One that leaks must not delete the fleet, or point someone else's
// server at another host and host key. So a machine syncs and removes only the servers it added itself.
func TestAMachineManagesOnlyTheServersItAdded(t *testing.T) {
	cfg, srv := newTestAPI(t)
	ws := testWorkspace.ID
	admin := clientOn(srv, header("Authorization",
		"Bearer "+seedMember(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)))
	accounts := nokkuv1connect.NewServiceAccountServiceClient(admin)
	machine := func() nokkuv1connect.TargetServiceClient {
		created, err := accounts.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
			Name: new(uniq("ci")),
		})
		require.NoError(t, err)
		id := created.GetServiceAccount().GetId()
		_, err = accounts.UpdateServiceAccount(t.Context(), masked(&nokkuv1.UpdateServiceAccountRequest{
			Id: &id, Role: new(nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR),
		}))
		require.NoError(t, err)
		key := serviceAccountToken(t, accounts, id, nil)
		return nokkuv1connect.NewTargetServiceClient(clientOn(srv, header("Authorization", "Bearer "+key)))
	}
	terraform, leaked := machine(), machine()
	person := nokkuv1connect.NewTargetServiceClient(clientOn(srv, header("Authorization",
		"Bearer "+seedMember(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR))))
	authority, err := nokkuv1connect.NewCertificateServiceClient(admin).
		GetCertificateAuthority(t.Context(), &nokkuv1.GetCertificateAuthorityRequest{})
	require.NoError(t, err)
	caKey := authority.GetCertificateAuthority().GetUserPublicKey()
	pinned, attacker := partialHostKey(t), partialHostKey(t)

	added, err := terraform.CreateTarget(t.Context(), &nokkuv1.CreateTargetRequest{
		Name: new(uniq("web")), Endpoints: []string{"10.0.0.2:22"}, HostPublicKey: &pinned,
	})
	require.NoError(t, err)
	own := added.GetTarget().GetId()
	// A server a person or a daemon brought is no machine's.
	byHand := seedTarget(t, cfg, ws)

	repin := func(as nokkuv1connect.TargetServiceClient, id string) error {
		_, err := as.SyncTargetUsers(t.Context(), &nokkuv1.SyncTargetUsersRequest{
			TargetId: &id, Usernames: []string{"root"}, HostPublicKey: &attacker, UserCaPublicKey: &caKey,
		})
		return err
	}
	remove := func(as nokkuv1connect.TargetServiceClient, id string) error {
		_, err := as.DeleteTarget(t.Context(), &nokkuv1.DeleteTargetRequest{Id: &id})
		return err
	}

	denied(t, repin(leaked, own), "a machine pinned a host key on a server another machine added")
	denied(t, remove(leaked, own), "a machine removed a server another machine added")
	denied(t, repin(terraform, byHand), "a machine pinned a host key on a server it did not add")
	denied(t, remove(terraform, byHand), "a machine removed a server it did not add")
	got, err := person.GetTarget(t.Context(), &nokkuv1.GetTargetRequest{Id: &own})
	require.NoError(t, err)
	assert.Equal(t, pinned, got.GetTarget().GetHostPublicKey(), "a refused sync changed the pinned host key")

	// Its own servers it syncs and removes. A person removes any, as in the web app.
	require.NoError(t, repin(terraform, own))
	require.NoError(t, remove(person, byHand))
	require.NoError(t, remove(terraform, own))
}

// The certificates page and nk ask for the servers a rollover left behind.
func TestListTargetsKeepsTheOnesARolloverLeftBehind(t *testing.T) {
	cfg, srv := newTestAPI(t)
	admin := partialConn(srv, seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN))
	behind := seedTarget(t, cfg, testWorkspace.ID)
	synced := seedTarget(t, cfg, testWorkspace.ID)
	neverSynced := seedTarget(t, cfg, testWorkspace.ID)
	touch := func(id string) {
		inWorkspace(t, cfg, testWorkspace.ID, func(q *db.Queries) error { return q.TouchTargetSync(t.Context(), id) })
	}

	touch(behind)
	_, err := nokkuv1connect.NewCertificateServiceClient(admin).
		RolloverCertificateAuthority(t.Context(), &nokkuv1.RolloverCertificateAuthorityRequest{})
	require.NoError(t, err)
	touch(synced)

	list, err := nokkuv1connect.NewTargetServiceClient(admin).ListTargets(t.Context(), &nokkuv1.ListTargetsRequest{
		Limit:          new(int32(50)),
		Ids:            []string{behind, synced, neverSynced},
		MissedRollover: new(true),
	})
	require.NoError(t, err)
	require.Len(t, list.GetTargets(), 1)
	assert.Equal(t, behind, list.GetTargets()[0].GetId())
	assert.EqualValues(t, 1, list.GetTotal())
}
