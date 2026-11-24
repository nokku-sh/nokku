//go:build integration

package api_test

import (
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
)

// An enroll token carries grants and tags. An ephemeral one approves on enroll.
func TestCreateJoinTokenWithGrants(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	member := seedUser(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	adminAuth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	tokens := nokkuv1connect.NewJoinTokenServiceClient(
		clientOn(srv, adminAuth),
	)

	created, err := tokens.CreateJoinToken(t.Context(), &nokkuv1.CreateJoinTokenRequest{
		Tags:      []string{"sandbox"},
		Ephemeral: new(true),
		Grants: []*nokkuv1.JoinTokenGrant{
			{Username: new("dev"), Subjects: []*nokkuv1.Subject{
				{Id: &member.ID, Kind: nokkuv1.SubjectKind_SUBJECT_KIND_USER.Enum()},
			}},
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
	subjects := token.GetGrants()[0].GetSubjects()
	require.Len(t, subjects, 1)
	assert.Equal(t, member.ID, subjects[0].GetId())
	assert.Equal(t, nokkuv1.SubjectKind_SUBJECT_KIND_USER, subjects[0].GetKind())

	_, err = tokens.CreateJoinToken(t.Context(), &nokkuv1.CreateJoinTokenRequest{
		Grants: []*nokkuv1.JoinTokenGrant{{Username: new("dev"), Subjects: []*nokkuv1.Subject{
			{Id: &member.ID, Kind: nokkuv1.SubjectKind_SUBJECT_KIND_TEAM.Enum()},
		}}},
	})
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "a user id is not a team, got %v", err)

	_, err = tokens.CreateJoinToken(t.Context(), &nokkuv1.CreateJoinTokenRequest{
		RetireAfter: durationpb.New(time.Hour),
	})
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "retire_after without ephemeral, got %v", err)
}
