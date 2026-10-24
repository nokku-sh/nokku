//go:build integration

package api_test

import (
	"testing"
	"uuid"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
)

func seedAccount(t *testing.T, cfg *config.Config) (*db.User, nokkuv1connect.AccountServiceClient) {
	t.Helper()
	u := seedUser(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	_, srv := newTestAPI(t)
	client := nokkuv1connect.NewAccountServiceClient(
		connect.NewClient(
			connecthttp.NewTransport(srv.Client(), srv.URL),
			header("Authorization", "Bearer "+sessionFor(t, cfg, u)),
		),
	)
	return u, client
}

// Without mail there is no way to confirm a new address.
func TestRequestEmailChangeNeedsMail(t *testing.T) {
	cfg, _ := newTestAPI(t)
	_, account := seedAccount(t, cfg)
	_, err := account.RequestEmailChange(t.Context(), &nokkuv1.RequestEmailChangeRequest{
		NewEmail: new(uuid.New().String() + "@api.test"),
	})
	assert.Equal(t, connect.CodeUnimplemented, connect.CodeOf(err), "got %v", err)
}

// The mails carry the tokens, so the links are taken from iam directly.
func TestConfirmAndCancelEmailChange(t *testing.T) {
	cfg, srv := newTestAPI(t)
	auth := nokkuv1connect.NewAuthServiceClient(connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL)))
	email := func(account nokkuv1connect.AccountServiceClient) (string, error) {
		got, err := account.GetAccount(t.Context(), &nokkuv1.GetAccountRequest{})
		return got.GetUser().GetEmail(), err
	}

	t.Run("cancel before confirm", func(t *testing.T) {
		u, account := seedAccount(t, cfg)
		confirm, cancel, err := cfg.IAM.RequestEmailChange(wsCtx(t, cfg), u, uuid.New().String()+"@api.test")
		require.NoError(t, err)

		_, err = auth.CancelEmailChange(t.Context(), &nokkuv1.CancelEmailChangeRequest{Token: &cancel})
		require.NoError(t, err)
		_, err = auth.ConfirmEmailChange(t.Context(), &nokkuv1.ConfirmEmailChangeRequest{Token: &confirm})
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "confirm after cancel: %v", err)

		got, err := email(account)
		require.NoError(t, err, "cancelling a pending change must not sign the user out")
		assert.Equal(t, u.Email, got)
	})

	t.Run("confirm then revert", func(t *testing.T) {
		u, account := seedAccount(t, cfg)
		newEmail := uuid.New().String() + "@api.test"
		confirm, cancel, err := cfg.IAM.RequestEmailChange(wsCtx(t, cfg), u, newEmail)
		require.NoError(t, err)

		_, err = auth.ConfirmEmailChange(t.Context(), &nokkuv1.ConfirmEmailChangeRequest{Token: &confirm})
		require.NoError(t, err)
		got, err := email(account)
		require.NoError(t, err)
		assert.Equal(t, newEmail, got)
		_, err = auth.ConfirmEmailChange(t.Context(), &nokkuv1.ConfirmEmailChangeRequest{Token: &confirm})
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "second confirm: %v", err)

		_, err = auth.CancelEmailChange(t.Context(), &nokkuv1.CancelEmailChangeRequest{Token: &cancel})
		require.NoError(t, err)
		_, err = email(account)
		assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "the revert signs everyone out: %v", err)
		reverted, err := cfg.IAM.GetUserByEmail(wsCtx(t, cfg), u.Email)
		require.NoError(t, err)
		assert.Equal(t, u.ID, reverted.ID)
	})
}

// The owner hands the workspace on before leaving, anyone else just goes.
func TestDeleteAccount(t *testing.T) {
	cfg, srv := newTestAPI(t)
	owner := nokkuv1connect.NewAccountServiceClient(
		connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), header(
			"Authorization",
			"Bearer "+seedMember(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER),
		)),
	)
	_, err := owner.DeleteAccount(t.Context(), &nokkuv1.DeleteAccountRequest{})
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err), "the owner left: %v", err)

	u, member := seedAccount(t, cfg)
	_, err = member.DeleteAccount(t.Context(), &nokkuv1.DeleteAccountRequest{})
	require.NoError(t, err)
	_, err = cfg.IAM.GetUserByEmail(wsCtx(t, cfg), u.Email)
	assert.Error(t, err, "the account is still there")
}
