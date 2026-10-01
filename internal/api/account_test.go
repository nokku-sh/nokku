package api

import (
	"testing"
	"uuid"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
)

const accountPassword = "correct horse battery"

// seedAccount returns a verified user and an account client signed in as them.
func seedAccount(t *testing.T, cfg *config.Config, password bool) (*db.User, nokkuv1connect.AccountServiceClient) {
	t.Helper()
	var u *db.User
	require.NoError(t, cfg.Conn.WithTx(t.Context(), func(q *db.Queries) (err error) {
		u, err = q.CreateUser(t.Context(), &db.CreateUserParams{Email: uuid.New().String() + "@api.test", Name: "u"})
		return err
	}))
	if password {
		require.NoError(t, cfg.IAM.Password.Store(t.Context(), u.ID, accountPassword))
	}
	_, token, err := cfg.IAM.IssueSession(t.Context(), iam.SessionParams{
		SubjectID: u.ID,
		Kind:      actor.KindUser,
		Method:    iam.MethodPassword,
	})
	require.NoError(t, err)
	_, srv := newTestAPI(t)
	return u, nokkuv1connect.NewAccountServiceClient(srv.Client(), srv.URL, header("Authorization", "Bearer "+token))
}

func TestRequestEmailChange(t *testing.T) {
	cfg, _ := newTestAPI(t)
	u, account := seedAccount(t, cfg, true)
	newEmail := uuid.New().String() + "@api.test"
	request := func(email, password string) error {
		_, err := account.RequestEmailChange(t.Context(), &nokkuv1.RequestEmailChangeRequest{
			NewEmail:        &email,
			CurrentPassword: &password,
		})
		return err
	}

	err := request(newEmail, "wrong")
	require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "wrong password: %v", err)
	assert.Empty(t, cfg.IAM.PendingEmail(t.Context(), u.ID), "a wrong password stored a pending change")

	require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(request(u.Email, accountPassword)), "same address")

	require.NoError(t, request(newEmail, accountPassword))
	got, err := account.GetAccount(t.Context(), &nokkuv1.GetAccountRequest{})
	require.NoError(t, err)
	assert.Equal(t, u.Email, got.GetUser().GetEmail(), "the address changed before it was confirmed")
	assert.Equal(t, newEmail, got.GetUser().GetPendingEmail())
}

func TestRequestEmailChangeRefused(t *testing.T) {
	cfg, _ := newTestAPI(t)
	newEmail := uuid.New().String() + "@api.test"
	password := accountPassword
	req := &nokkuv1.RequestEmailChangeRequest{NewEmail: &newEmail, CurrentPassword: &password}

	_, passwordless := seedAccount(t, cfg, false)
	_, err := passwordless.RequestEmailChange(t.Context(), req)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err), "no password: %v", err)

	// The identity provider owns the address, even with a password set.
	u, sso := seedAccount(t, cfg, true)
	require.NoError(t, cfg.Conn.WithTx(t.Context(), func(q *db.Queries) error {
		_, err := q.UpsertCredential(t.Context(), &db.UpsertCredentialParams{
			ID: uuid.New().
				String(),
			UserID:   u.ID,
			Type:     string(iam.MethodOIDC),
			Provider: "idp",
			Subject:  u.ID,
			Data:     []byte("{}"),
		})
		return err
	}))
	_, err = sso.RequestEmailChange(t.Context(), req)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err), "sso account: %v", err)
	assert.Empty(t, cfg.IAM.PendingEmail(t.Context(), u.ID))
}

// The mails carry the tokens, so the links are taken from iam directly.
func TestConfirmAndCancelEmailChange(t *testing.T) {
	cfg, srv := newTestAPI(t)
	auth := nokkuv1connect.NewAuthServiceClient(srv.Client(), srv.URL)
	email := func(account nokkuv1connect.AccountServiceClient) (string, error) {
		got, err := account.GetAccount(t.Context(), &nokkuv1.GetAccountRequest{})
		return got.GetUser().GetEmail(), err
	}

	t.Run("cancel before confirm", func(t *testing.T) {
		u, account := seedAccount(t, cfg, true)
		confirm, cancel, err := cfg.IAM.RequestEmailChange(t.Context(), u, uuid.New().String()+"@api.test")
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
		u, account := seedAccount(t, cfg, true)
		newEmail := uuid.New().String() + "@api.test"
		confirm, cancel, err := cfg.IAM.RequestEmailChange(t.Context(), u, newEmail)
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
		reverted, err := cfg.IAM.GetUserByEmail(t.Context(), u.Email)
		require.NoError(t, err)
		assert.Equal(t, u.ID, reverted.ID)
	})
}
