//go:build integration

package api_test

import (
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"
)

// An enroll token carries grants and tags for the targets it makes. An ephemeral one is approved on enroll
// and retires after a default when no interval is given.
func TestCreateJoinTokenWithGrants(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	member := seedUser(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	adminAuth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	tokens := nokkuv1connect.NewJoinTokenServiceClient(srv.Client(), srv.URL, adminAuth)

	created, err := tokens.CreateJoinToken(t.Context(), &nokkuv1.CreateJoinTokenRequest{
		Kind:      nokkuv1.JoinTokenKind_JOIN_TOKEN_KIND_ENROLL.Enum(),
		Tags:      []string{"sandbox"},
		Ephemeral: new(true),
		Grants: []*nokkuv1.JoinTokenGrant{
			{Username: new("dev"), UserIds: []string{member.ID}},
		},
	})
	require.NoError(t, err)
	assert.True(t, created.GetToken().GetAutoApprove(), "an ephemeral token approves on enroll")
	assert.Equal(t, 15*time.Minute, created.GetToken().GetRetireAfter().AsDuration())

	listed, err := tokens.ListJoinTokens(t.Context(), &nokkuv1.ListJoinTokensRequest{})
	require.NoError(t, err)
	i := slices.IndexFunc(listed.GetTokens(), func(t *nokkuv1.JoinToken) bool {
		return t.GetId() == created.GetToken().GetId()
	})
	require.NotEqual(t, -1, i, "the token is not listed")
	token := listed.GetTokens()[i]
	assert.Equal(t, []string{"sandbox"}, token.GetTags())
	require.Len(t, token.GetGrants(), 1)
	assert.Equal(t, "dev", token.GetGrants()[0].GetUsername())
	assert.Equal(t, []string{member.ID}, token.GetGrants()[0].GetUserIds())

	_, err = tokens.CreateJoinToken(t.Context(), &nokkuv1.CreateJoinTokenRequest{
		Kind:   nokkuv1.JoinTokenKind_JOIN_TOKEN_KIND_ENROLL.Enum(),
		Grants: []*nokkuv1.JoinTokenGrant{{Username: new("dev"), TeamIds: []string{member.ID}}},
	})
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "a user id is not a team, got %v", err)

	_, err = tokens.CreateJoinToken(t.Context(), &nokkuv1.CreateJoinTokenRequest{
		Kind:        nokkuv1.JoinTokenKind_JOIN_TOKEN_KIND_ENROLL.Enum(),
		RetireAfter: durationpb.New(time.Hour),
	})
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "retire_after without ephemeral, got %v", err)

	_, err = tokens.CreateJoinToken(t.Context(), &nokkuv1.CreateJoinTokenRequest{
		Kind:   nokkuv1.JoinTokenKind_JOIN_TOKEN_KIND_INVITE.Enum(),
		Grants: []*nokkuv1.JoinTokenGrant{{Username: new("dev"), UserIds: []string{member.ID}}},
	})
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "grants on an invite, got %v", err)
}
