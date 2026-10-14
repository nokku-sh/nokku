package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/cli/internal/state"
)

const (
	aliceID = "0199a0a0-0000-7000-8000-00000000000a"
	opsID   = "0199a0a0-0000-7000-8000-00000000000b"
	ciID    = "0199a0a0-0000-7000-8000-00000000000c"
	otherID = "0199a0a0-0000-7000-8000-00000000000d"
)

// The fakes answer like the core's substring search, so a lookup must pick the exact match.
type fakeUsers struct {
	nokkuv1connect.UnimplementedWorkspaceServiceHandler
}

func (fakeUsers) ListUsers(context.Context, *nokkuv1.ListUsersRequest) (*nokkuv1.ListUsersResponse, error) {
	return &nokkuv1.ListUsersResponse{Users: []*nokkuv1.User{
		{Id: new(otherID), Email: new("malice@example.com")},
		{Id: new(aliceID), Email: new("alice@example.com")},
	}}, nil
}

type fakeTeams struct {
	nokkuv1connect.UnimplementedTeamServiceHandler
}

func (fakeTeams) ListTeams(context.Context, *nokkuv1.ListTeamsRequest) (*nokkuv1.ListTeamsResponse, error) {
	return &nokkuv1.ListTeamsResponse{Teams: []*nokkuv1.Team{
		{Id: new(opsID), Name: new("ops")},
		{Id: new(otherID), Name: new("devops")},
		{Id: new(aliceID), Name: new("twins")},
		{Id: new(otherID), Name: new("twins")},
	}}, nil
}

type fakeServiceAccounts struct {
	nokkuv1connect.UnimplementedServiceAccountServiceHandler
}

func (fakeServiceAccounts) ListServiceAccounts(
	context.Context,
	*nokkuv1.ListServiceAccountsRequest,
) (*nokkuv1.ListServiceAccountsResponse, error) {
	return &nokkuv1.ListServiceAccountsResponse{ServiceAccounts: []*nokkuv1.ServiceAccount{
		{Id: new(ciID), Name: new("ci")},
	}}, nil
}

func newGrantTestClient(t *testing.T) *Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(nokkuv1connect.NewWorkspaceServiceHandler(fakeUsers{}))
	mux.Handle(nokkuv1connect.NewTeamServiceHandler(fakeTeams{}))
	mux.Handle(nokkuv1connect.NewServiceAccountServiceHandler(fakeServiceAccounts{}))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	c := &Client{State: &state.State{APIURL: server.URL}}
	c.State.User = &state.User{ID: "me-user"}
	c.users = nokkuv1connect.NewWorkspaceServiceClient(http.DefaultClient, server.URL)
	c.teams = nokkuv1connect.NewTeamServiceClient(http.DefaultClient, server.URL)
	c.serviceAccounts = nokkuv1connect.NewServiceAccountServiceClient(http.DefaultClient, server.URL)
	return c
}

func TestResolveGrants(t *testing.T) {
	t.Parallel()
	c := newGrantTestClient(t)

	grants, err := c.ResolveGrants(t.Context(), []string{
		"root=team:" + otherID,
		"deploy = me, Alice@example.com",
		"deploy=team:ops,sa:ci",
	})
	require.NoError(t, err)
	assert.Equal(t, []Grant{
		{
			Account:         "deploy",
			Subjects:        []string{"me", "Alice@example.com", "team:ops", "sa:ci"},
			Users:           []string{"me-user", aliceID},
			Teams:           []string{opsID},
			ServiceAccounts: []string{ciID},
		},
		{Account: "root", Subjects: []string{"team:" + otherID}, Teams: []string{otherID}},
	}, grants, "an account named twice gets both, a near miss is no match, an id is taken as it is")

	grants, err = c.ResolveGrants(t.Context(), nil)
	require.NoError(t, err)
	assert.Empty(t, grants)
}

func TestResolveGrantsMeAsServiceAccount(t *testing.T) {
	t.Parallel()
	c := newGrantTestClient(t)
	c.State.User = nil
	c.State.ServiceAccount = &state.ServiceAccount{ID: "me-sa"}

	grants, err := c.ResolveGrants(t.Context(), []string{"root=me"})
	require.NoError(t, err)
	assert.Equal(t, []Grant{{Account: "root", Subjects: []string{"me"}, ServiceAccounts: []string{"me-sa"}}}, grants)
}

func TestResolveGrantsRefuses(t *testing.T) {
	t.Parallel()
	c := newGrantTestClient(t)

	for spec, want := range map[string]string{
		"root=bob@example.com": "no user",
		"root=team:twins":      "several teams",
		"root=team:Ops":        "no team",
		"root=sa:deploy":       "no service account",
		"root=group:ops":       "is not me",
		"root":                 "account=subject",
		"root=":                "account=subject",
		"=me":                  "account=subject",
		"root=,":               "account=subject",
	} {
		_, err := c.ResolveGrants(t.Context(), []string{spec})
		require.ErrorContains(t, err, want, spec)
	}
}
