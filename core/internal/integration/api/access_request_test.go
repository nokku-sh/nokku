//go:build integration

package api_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/api"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
)

// enterpriseServer serves the test workspace on an Enterprise license of its own, the shared server stays unlicensed.
func enterpriseServer(t *testing.T) *httptest.Server {
	t.Helper()
	_, srv := enterprise(t)
	return srv
}

// enterprise is enterpriseServer with the config it runs on, for what runs beside the server.
func enterprise(t *testing.T) (*config.Config, *httptest.Server) {
	t.Helper()
	cfg, _ := newTestAPI(t)
	pubHex, key := issueLicense(t, entitlement.PlanEnterprise)

	local := *cfg
	var err error
	local.Entitlements, err = entitlement.New(t.Context(), cfg.Conn, pubHex, modeSelfHosted)
	require.NoError(t, err)
	srv := httptest.NewServer(api.New(&local).Handler(t.Context()))
	t.Cleanup(srv.Close)

	owner := seedMember(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER)
	_, err = nokkuv1connect.NewBillingServiceClient(srv.Client(), srv.URL, header("Authorization", "Bearer "+owner)).
		ActivateLicense(t.Context(), &nokkuv1.ActivateLicenseRequest{Key: &key})
	require.NoError(t, err)
	return &local, srv
}

func TestAccessRequestFlow(t *testing.T) {
	cfg, _ := newTestAPI(t)
	srv := enterpriseServer(t)
	ws := seedWorkspace(t, cfg)
	ctx := t.Context()

	tag := uniq("prod")
	var target *db.Target
	inWorkspace(t, cfg, ws, func(q *db.Queries) (err error) {
		if target, err = q.CreateTarget(
			ctx,
			&db.CreateTargetParams{Name: uniq("db"), Tags: []string{tag}},
		); err != nil {
			return err
		}
		_, err = q.CreateTargetAccount(ctx, &db.CreateTargetAccountParams{TargetID: target.ID, Username: "postgres"})
		return err
	})
	hidden := seedTarget(t, cfg, ws)

	member := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	as := func(u *db.User) nokkuv1connect.AccessRequestServiceClient {
		return nokkuv1connect.NewAccessRequestServiceClient(srv.Client(), srv.URL,
			header("Authorization", "Bearer "+sessionFor(t, cfg, u)))
	}
	asMember := as(member)
	admin := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)
	asAdmin := as(admin)

	_, err := asAdmin.SetRequestableTags(ctx, &nokkuv1.SetRequestableTagsRequest{Tags: []string{tag}})
	require.NoError(t, err)

	listed, err := asMember.ListRequestableAccounts(ctx, &nokkuv1.ListRequestableAccountsRequest{})
	require.NoError(t, err)
	var names []string
	for _, rt := range listed.GetTargets() {
		names = append(names, rt.GetName())
		assert.NotEqual(t, hidden, rt.GetId(), "a target without a requestable tag must stay hidden")
	}
	assert.Contains(t, names, target.Name)

	ask := func(c nokkuv1connect.AccessRequestServiceClient, targetName string) (*nokkuv1.AccessRequest, error) {
		res, err := c.CreateAccessRequest(ctx, &nokkuv1.CreateAccessRequestRequest{
			Target:   &targetName,
			Username: new("postgres"),
			Duration: durationpb.New(time.Hour),
			Reason:   new("fix the replica"),
		})
		return res.GetRequest(), err
	}

	_, err = ask(asMember, hidden)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "a hidden target must look like none, got %v", err)

	req, err := ask(asMember, target.Name)
	require.NoError(t, err)
	assert.Equal(t, nokkuv1.AccessRequestStatus_ACCESS_REQUEST_STATUS_PENDING, req.GetStatus())

	_, err = ask(asMember, target.Name)
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err), "one open request per account, got %v", err)

	_, err = asMember.ApproveAccessRequest(ctx, &nokkuv1.ApproveAccessRequestRequest{Id: new(req.GetId())})
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "a member must not approve, got %v", err)

	approved, err := asAdmin.ApproveAccessRequest(ctx, &nokkuv1.ApproveAccessRequestRequest{Id: new(req.GetId())})
	require.NoError(t, err)
	until := approved.GetRequest().GetGrantedUntil().AsTime()
	assert.WithinDuration(t, time.Now().Add(time.Hour), until, time.Minute)

	var rows []*db.ListSubjectUsernamesForTargetsRow
	inWorkspace(t, cfg, ws, func(q *db.Queries) (err error) {
		rows, err = q.ListSubjectUsernamesForTargets(ctx, &db.ListSubjectUsernamesForTargetsParams{
			TargetIds: []string{target.ID},
			SubjectID: member.ID,
		})
		return err
	})
	require.Len(t, rows, 1, "the approval must grant the account")
	require.NotNil(t, rows[0].Until(), "the grant must end")
	assert.WithinDuration(t, until, *rows[0].Until(), time.Second)

	_, err = asAdmin.DenyAccessRequest(ctx, &nokkuv1.DenyAccessRequestRequest{Id: new(req.GetId())})
	assert.Equal(
		t,
		connect.CodeFailedPrecondition,
		connect.CodeOf(err),
		"an answered request stays answered, got %v",
		err,
	)

	own, err := ask(asAdmin, target.Name)
	require.NoError(t, err)
	_, err = asAdmin.ApproveAccessRequest(ctx, &nokkuv1.ApproveAccessRequestRequest{Id: new(own.GetId())})
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "nobody approves their own request, got %v", err)

	mine, err := asMember.ListAccessRequests(ctx, &nokkuv1.ListAccessRequestsRequest{})
	require.NoError(t, err)
	for _, r := range mine.GetRequests() {
		assert.Equal(t, member.ID, r.GetRequesterId(), "a member sees only their own requests")
	}
	_, err = asMember.GetAccessRequest(ctx, &nokkuv1.GetAccessRequestRequest{Id: new(own.GetId())})
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "nor can they open another one, got %v", err)

	_, err = asAdmin.CancelAccessRequest(ctx, &nokkuv1.CancelAccessRequestRequest{Id: new(own.GetId())})
	require.NoError(t, err)
	_, err = asAdmin.SetRequestableTags(ctx, &nokkuv1.SetRequestableTagsRequest{})
	require.NoError(t, err)
}

// A zero timeout must replace a stored one. A merge would keep the old one, and nobody could turn it off.
func TestIdleTimeoutTurnsOff(t *testing.T) {
	cfg, _ := newTestAPI(t)
	srv := enterpriseServer(t)
	owner := seedMember(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER)
	client := nokkuv1connect.NewWorkspaceServiceClient(srv.Client(), srv.URL, header("Authorization", "Bearer "+owner))
	set := func(d time.Duration) *nokkuv1.WorkspaceSettings {
		res, err := client.UpdateWorkspace(t.Context(), &nokkuv1.UpdateWorkspaceRequest{
			Settings: &nokkuv1.WorkspaceSettings{SessionIdleTimeout: durationpb.New(d)},
		})
		require.NoError(t, err)
		return res.GetWorkspace().GetSettings()
	}

	assert.Equal(t, 15*time.Minute, set(15*time.Minute).GetSessionIdleTimeout().AsDuration())
	assert.Zero(t, set(0).GetSessionIdleTimeout().AsDuration(), "turning the timeout off must stick")
}
