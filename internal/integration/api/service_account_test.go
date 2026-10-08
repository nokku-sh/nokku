//go:build integration

package api_test

import (
	"strings"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/db"
)

func TestUpdateServiceAccount(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	auth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	client := nokkuv1connect.NewServiceAccountServiceClient(srv.Client(), srv.URL, auth)

	created, err := client.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
		Name: new("deploy"),
		Tags: []string{"ci"},
	})
	require.NoError(t, err)
	id := created.GetServiceAccount().GetId()

	updated, err := client.UpdateServiceAccount(t.Context(), &nokkuv1.UpdateServiceAccountRequest{
		Id:   &id,
		Tags: []string{"ci", "prod"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"ci", "prod"}, updated.GetServiceAccount().GetTags(), "tags must be saved")
	assert.Equal(
		t,
		created.GetServiceAccount().GetName(),
		updated.GetServiceAccount().GetName(),
		"unset fields stay as they are",
	)

	cleared, err := client.UpdateServiceAccount(t.Context(), &nokkuv1.UpdateServiceAccountRequest{
		Id: &id,
	})
	require.NoError(t, err)
	assert.Empty(t, cleared.GetServiceAccount().GetTags(), "an update replaces the tags, the last one can go")
}

func TestServiceAccountRole(t *testing.T) {
	cfg, srv := newTestAPI(t)
	auth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	client := nokkuv1connect.NewServiceAccountServiceClient(srv.Client(), srv.URL, auth)

	created, err := client.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
		Name: new(uniq("sa")),
	})
	require.NoError(t, err)
	id := created.GetServiceAccount().GetId()
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER, created.GetServiceAccount().GetRole(),
		"no role is the member")

	update := func(role *nokkuv1.WorkspaceRole) (nokkuv1.WorkspaceRole, error) {
		res, err := client.UpdateServiceAccount(t.Context(), &nokkuv1.UpdateServiceAccountRequest{Id: &id, Role: role})
		return res.GetServiceAccount().GetRole(), err
	}
	got, err := update(new(nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR))
	require.NoError(t, err)
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR, got)

	got, err = update(nil)
	require.NoError(t, err)
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR, got, "an update without a role keeps it")

	got, err = update(new(nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER))
	require.NoError(t, err)
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER, got, "the member can be named")

	_, err = update(new(nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err),
		"the editor is the most a service account can be")

	// The table refuses it too, whatever a caller gets past the API.
	err = cfg.Conn.TenantTx(wsCtx(t, cfg), func(q *db.Queries) error {
		_, err := q.CreateServiceAccount(t.Context(), &db.CreateServiceAccountParams{
			Name: uniq("sa"),
			Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN,
		})
		return err
	})
	assert.Error(t, err, "the table took a service account above the editor")
}

// serviceAccountToken makes a token for the account and returns its secret.
func serviceAccountToken(
	t *testing.T,
	client nokkuv1connect.ServiceAccountServiceClient,
	id string,
	expiresAt *timestamppb.Timestamp,
) string {
	t.Helper()
	res, err := client.CreateServiceAccountToken(t.Context(), &nokkuv1.CreateServiceAccountTokenRequest{
		ServiceAccountId: &id,
		ExpiresAt:        expiresAt,
	})
	require.NoError(t, err)
	return res.GetSecret()
}

// A service account holds any number of tokens. Each is revoked on its own,
// so a new one can be rolled out before the old one goes.
func TestServiceAccountTokens(t *testing.T) {
	cfg, srv := newTestAPI(t)
	auth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	client := nokkuv1connect.NewServiceAccountServiceClient(srv.Client(), srv.URL, auth)

	created, err := client.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
		Name: new(uniq("sa")),
	})
	require.NoError(t, err)
	id := created.GetServiceAccount().GetId()
	assert.Nil(t, created.GetServiceAccount().GetLastUsedAt(), "a new account was never used")

	expiry := time.Now().Add(time.Hour)
	first, err := client.CreateServiceAccountToken(t.Context(), &nokkuv1.CreateServiceAccountTokenRequest{
		ServiceAccountId: &id,
		Label:            new("deploy"),
		ExpiresAt:        timestamppb.New(expiry),
	})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(first.GetSecret(), "nk_sa_"), "the secret is %q", first.GetSecret())
	assert.Equal(t, "deploy", first.GetToken().GetLabel())
	assert.WithinDuration(t, expiry, first.GetToken().GetExpiresAt().AsTime(), time.Second)
	second, err := client.CreateServiceAccountToken(t.Context(), &nokkuv1.CreateServiceAccountTokenRequest{
		ServiceAccountId: &id,
	})
	require.NoError(t, err)
	assert.Nil(t, second.GetToken().GetExpiresAt(), "an expiry that is left out never expires")

	whoami := func(token string) (string, error) {
		res, err := nokkuv1connect.NewUtilServiceClient(
			srv.Client(), srv.URL, header("Authorization", "Bearer "+token),
		).Whoami(t.Context(), &nokkuv1.WhoamiRequest{})
		return res.GetSubjectId(), err
	}
	for _, secret := range []string{first.GetSecret(), second.GetSecret()} {
		got, err := whoami(secret)
		require.NoError(t, err)
		assert.Equal(t, id, got, "every token signs in as the account")
	}

	list, err := client.ListServiceAccountTokens(t.Context(), &nokkuv1.ListServiceAccountTokensRequest{
		ServiceAccountId: &id,
	})
	require.NoError(t, err)
	require.Len(t, list.GetTokens(), 2)
	for _, tok := range list.GetTokens() {
		assert.NotNil(t, tok.GetLastUsedAt(), "a used token shows when")
	}
	account, err := client.GetServiceAccount(t.Context(), &nokkuv1.GetServiceAccountRequest{Id: &id})
	require.NoError(t, err)
	assert.NotNil(t, account.GetServiceAccount().GetLastUsedAt(), "the account shows when a token was last used")

	_, err = client.RevokeServiceAccountToken(t.Context(), &nokkuv1.RevokeServiceAccountTokenRequest{
		ServiceAccountId: &id,
		Id:               new(first.GetToken().GetId()),
	})
	require.NoError(t, err)
	_, err = whoami(first.GetSecret())
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "a revoked token still signs in, got %v", err)
	_, err = whoami(second.GetSecret())
	require.NoError(t, err, "revoking one token ended another")

	_, err = client.RevokeServiceAccountToken(t.Context(), &nokkuv1.RevokeServiceAccountTokenRequest{
		ServiceAccountId: new(uuid.NewV7().String()),
		Id:               new(second.GetToken().GetId()),
	})
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "a token revoked through another account, got %v", err)
	_, err = whoami(second.GetSecret())
	require.NoError(t, err, "a refused revoke ended the token")

	_, err = client.CreateServiceAccountToken(t.Context(), &nokkuv1.CreateServiceAccountTokenRequest{
		ServiceAccountId: &id,
		ExpiresAt:        timestamppb.New(time.Now().Add(-time.Minute)),
	})
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "an expiry in the past, got %v", err)
}
