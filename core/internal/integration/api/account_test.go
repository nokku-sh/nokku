//go:build integration

package api_test

import (
	"context"
	"testing"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/app"
	"github.com/nokku-sh/nokku/core/internal/db"
)

func seedAccount(t *testing.T, cfg *app.Config) (*db.User, nokkuv1connect.AccountServiceClient) {
	t.Helper()
	u := seedUser(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	_, srv := newTestAPI(t)
	client := nokkuv1connect.NewAccountServiceClient(
		clientOn(srv, header("Authorization", "Bearer "+sessionFor(t, cfg, u))),
	)
	return u, client
}

// Without mail there is no way to confirm a new address.
func TestRequestEmailChangeNeedsMail(t *testing.T) {
	cfg, _ := newTestAPI(t)
	_, account := seedAccount(t, cfg)
	_, err := account.RequestEmailChange(t.Context(), &nokkuv1.RequestEmailChangeRequest{
		NewEmail: new(newMailAddress()),
	})
	assert.Equal(t, connect.CodeUnimplemented, connect.CodeOf(err), "got %v", err)
}

// The mails carry the tokens, so the links are taken from iam directly.
func TestConfirmAndCancelEmailChange(t *testing.T) {
	cfg, srv := newTestAPI(t)
	auth := nokkuv1connect.NewAuthServiceClient(clientOn(srv))
	email := func(account nokkuv1connect.AccountServiceClient) (string, error) {
		got, err := account.GetAccount(t.Context(), &nokkuv1.GetAccountRequest{})
		return got.GetUser().GetEmail(), err
	}

	t.Run("cancel before confirm", func(t *testing.T) {
		u, account := seedAccount(t, cfg)
		confirm, cancel, err := cfg.IAM.RequestEmailChange(wsCtx(t), u, newMailAddress())
		require.NoError(t, err)

		_, err = auth.CancelEmailChange(t.Context(), &nokkuv1.CancelEmailChangeRequest{Token: &cancel})
		require.NoError(t, err)
		_, err = auth.ConfirmEmailChange(t.Context(), &nokkuv1.ConfirmEmailChangeRequest{Token: &confirm})
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "confirm after cancel: %v", err)

		// Whoever asked for the change held a session, "this wasn't me" ends it.
		_, err = email(account)
		assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "the cancel signs everyone out: %v", err)
		kept, err := cfg.Conn.Tenant().GetUserByEmail(wsCtx(t), u.Email)
		require.NoError(t, err)
		assert.Equal(t, u.ID, kept.ID)
	})

	t.Run("confirm then revert", func(t *testing.T) {
		u, account := seedAccount(t, cfg)
		newEmail := newMailAddress()
		confirm, cancel, err := cfg.IAM.RequestEmailChange(wsCtx(t), u, newEmail)
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
		reverted, err := cfg.Conn.Tenant().GetUserByEmail(wsCtx(t), u.Email)
		require.NoError(t, err)
		assert.Equal(t, u.ID, reverted.ID)
	})

	t.Run("revert after the old address was taken", func(t *testing.T) {
		u, account := seedAccount(t, cfg)
		confirm, cancel, err := cfg.IAM.RequestEmailChange(wsCtx(t), u, newMailAddress())
		require.NoError(t, err)
		_, err = auth.ConfirmEmailChange(t.Context(), &nokkuv1.ConfirmEmailChangeRequest{Token: &confirm})
		require.NoError(t, err)
		inWorkspace(t, cfg, testWorkspace.ID, func(q *db.Queries) error {
			_, err := q.CreateUser(t.Context(), &db.CreateUserParams{
				Email: u.Email, Name: "other", Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
			})
			return err
		})

		_, err = auth.CancelEmailChange(t.Context(), &nokkuv1.CancelEmailChangeRequest{Token: &cancel})
		assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err), "got %v", err)
		_, err = email(account)
		assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "the changer is still signed in: %v", err)
	})
}

// Passkeys and linked identities come back as the two lists they are.
func TestListCredentials(t *testing.T) {
	cfg, _ := newTestAPI(t)
	u, account := seedAccount(t, cfg)
	// Without a config the row breaks ListSSOProviders, so it goes again.
	provider := uniq("idp")
	ctx := actor.WithWorkspace(t.Context(), actor.Workspace{ID: testWorkspace.ID})
	_, err := cfg.Conn.Pool.Exec(ctx, `INSERT INTO sso_providers (provider_id, enabled, config) VALUES ($1, FALSE, '')`,
		provider)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := cfg.Conn.Pool.Exec(context.WithoutCancel(ctx), "DELETE FROM sso_providers WHERE provider_id = $1",
			provider)
		require.NoError(t, err)
	})
	var identity string
	inWorkspace(t, cfg, testWorkspace.ID, func(q *db.Queries) (err error) {
		if _, err = q.SavePasskey(t.Context(), &db.SavePasskeyParams{
			UserID: u.ID, CredentialID: u.ID, Data: []byte{}, Label: "laptop",
		}); err != nil {
			return err
		}
		identity, err = q.LinkOIDCIdentity(t.Context(), &db.LinkOIDCIdentityParams{
			UserID: u.ID, ProviderID: provider, Subject: u.ID,
		})
		return err
	})

	res, err := account.ListCredentials(t.Context(), &nokkuv1.ListCredentialsRequest{})
	require.NoError(t, err)
	require.Len(t, res.GetPasskeys(), 1)
	assert.Equal(t, "laptop", res.GetPasskeys()[0].GetLabel())
	require.Len(t, res.GetOidcIdentities(), 1)
	assert.Equal(t, identity, res.GetOidcIdentities()[0].GetId())
	assert.Equal(t, provider, res.GetOidcIdentities()[0].GetProvider())
}

// The owner hands the workspace on before leaving, anyone else just goes.
func TestDeleteAccount(t *testing.T) {
	cfg, srv := newTestAPI(t)
	owner := nokkuv1connect.NewAccountServiceClient(
		clientOn(srv, header(
			"Authorization",
			"Bearer "+seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER),
		)),
	)
	_, err := owner.DeleteAccount(t.Context(), &nokkuv1.DeleteAccountRequest{})
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err), "the owner left: %v", err)

	u, member := seedAccount(t, cfg)
	_, err = member.DeleteAccount(t.Context(), &nokkuv1.DeleteAccountRequest{})
	require.NoError(t, err)
	_, err = cfg.Conn.Tenant().GetUserByEmail(wsCtx(t), u.Email)
	assert.Error(t, err, "the account is still there")
}
