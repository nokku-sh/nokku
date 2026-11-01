//go:build integration

package api_test

import (
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/iam"
)

// Without mail the admin gets the link. An invite never makes an owner.
func TestInvitationWithoutMail(t *testing.T) {
	// Enterprise seats, the community cap runs out in the shared workspace.
	base, _ := enterprise(t)
	cfg, srv := iamServer(t, base, iam.Deps{})
	ctx := t.Context()
	inviter := seedUser(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)
	admin := browserSession(t, cfg, inviter, 0)
	invitations := nokkuv1connect.NewInvitationServiceClient(clientOn(srv, signedIn(t, cfg, admin)))
	public := nokkuv1connect.NewInvitationServiceClient(clientOn(srv))
	email := newMailAddress()

	created, err := invitations.CreateInvitation(ctx, &nokkuv1.CreateInvitationRequest{
		Email: new(strings.ToUpper(email)),
		Role:  nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR.Enum(),
	})
	require.NoError(t, err)
	assert.Equal(t, email, created.GetInvitation().GetEmail(), "the address is kept in lower case")
	require.NotEmpty(t, created.GetLink(), "a server without mail returned no link")
	token := tokenOf(t, created.GetLink())

	opened, err := public.GetInvitation(ctx, &nokkuv1.GetInvitationRequest{Token: &token})
	require.NoError(t, err)
	assert.Equal(t, email, opened.GetEmail())
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR, opened.GetRole())

	listed, err := invitations.ListInvitations(ctx, &nokkuv1.ListInvitationsRequest{})
	require.NoError(t, err)
	assert.True(t, slices.ContainsFunc(listed.GetInvitations(), func(i *nokkuv1.Invitation) bool {
		return i.GetEmail() == email
	}), "the invite is not listed")

	_, err = invitations.CreateInvitation(ctx, &nokkuv1.CreateInvitationRequest{
		Email: new(newMailAddress()),
		Role:  nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER.Enum(),
	})
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "an invite to own the workspace, got %v", err)

	_, err = invitations.DeleteInvitation(ctx, &nokkuv1.DeleteInvitationRequest{Email: &email})
	require.NoError(t, err)
	_, err = public.GetInvitation(ctx, &nokkuv1.GetInvitationRequest{Token: &token})
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err), "a revoked invite still opens, got %v", err)
	_, err = invitations.DeleteInvitation(ctx, &nokkuv1.DeleteInvitationRequest{Email: &email})
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "a second revoke, got %v", err)
}
