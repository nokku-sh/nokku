//go:build integration

package api_test

import (
	"strings"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/db"
)

func TestUpdateServiceAccount(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	auth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	client := nokkuv1connect.NewServiceAccountServiceClient(
		clientOn(srv, auth),
	)

	created, err := client.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
		Name: new("deploy"),
		Tags: []string{"ci"},
	})
	require.NoError(t, err)
	id := created.GetServiceAccount().GetId()

	updated, err := client.UpdateServiceAccount(t.Context(), masked(&nokkuv1.UpdateServiceAccountRequest{
		Id:   &id,
		Tags: []string{"ci", "prod"},
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"ci", "prod"}, updated.GetServiceAccount().GetTags(), "tags must be saved")
	assert.Equal(
		t,
		created.GetServiceAccount().GetName(),
		updated.GetServiceAccount().GetName(),
		"unset fields stay as they are",
	)

	kept, err := client.UpdateServiceAccount(t.Context(), masked(&nokkuv1.UpdateServiceAccountRequest{
		Id:   &id,
		Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER.Enum(),
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"ci", "prod"}, kept.GetServiceAccount().GetTags(), "a role change wiped the tags")

	cleared, err := client.UpdateServiceAccount(t.Context(), &nokkuv1.UpdateServiceAccountRequest{
		Id:         &id,
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"tags"}},
	})
	require.NoError(t, err)
	assert.Empty(t, cleared.GetServiceAccount().GetTags(), "naming the tags with none clears them")
}

// Limits are stored the way a server reads them, an unreadable list is refused.
func TestServiceAccountLimits(t *testing.T) {
	cfg, srv := newTestAPI(t)
	client := nokkuv1connect.NewServiceAccountServiceClient(
		clientOn(srv, header(
			"Authorization",
			"Bearer "+seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
		)),
	)

	_, err := client.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
		Name: new(uniq("limited")), SourceAddress: new("the office"),
	})
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "got %v", err)

	created, err := client.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
		Name:          new(uniq("limited")),
		ForceCommand:  new(" /usr/local/bin/deploy "),
		SourceAddress: new("10.0.0.0/8, 192.0.2.7"),
	})
	require.NoError(t, err)
	account := created.GetServiceAccount()
	assert.Equal(t, "/usr/local/bin/deploy", account.GetForceCommand())
	assert.Equal(t, "10.0.0.0/8,192.0.2.7", account.GetSourceAddress())

	_, err = client.UpdateServiceAccount(t.Context(), masked(&nokkuv1.UpdateServiceAccountRequest{
		Id: account.Id, SourceAddress: new("the office"),
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "got %v", err)

	// An update naming neither keeps both, an empty one takes the limit away.
	renamed, err := client.UpdateServiceAccount(t.Context(), masked(&nokkuv1.UpdateServiceAccountRequest{
		Id: account.Id, Description: new("changed"),
	}))
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.0/8,192.0.2.7", renamed.GetServiceAccount().GetSourceAddress())
	cleared, err := client.UpdateServiceAccount(t.Context(), masked(&nokkuv1.UpdateServiceAccountRequest{
		Id: account.Id, SourceAddress: new(""),
	}))
	require.NoError(t, err)
	assert.Empty(t, cleared.GetServiceAccount().GetSourceAddress())
	assert.Equal(t, "/usr/local/bin/deploy", cleared.GetServiceAccount().GetForceCommand())
}

// Only a person changes what limits a machine. Else an editor account lifts its
// own limits, and a CI job rolls the CA over.
func TestMachinesDoNotChangeTheirLimits(t *testing.T) {
	cfg, srv := newTestAPI(t)
	u := seedUser(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)
	person := header("Authorization", "Bearer "+sessionFor(t, cfg, u))
	accounts := nokkuv1connect.NewServiceAccountServiceClient(
		clientOn(srv, person),
	)
	created, err := accounts.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
		Name:          new(uniq("editor")),
		Role:          nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR.Enum(),
		ForceCommand:  new("/usr/local/bin/deploy"),
		SourceAddress: new("10.0.0.0/8"),
	})
	require.NoError(t, err)
	id := created.GetServiceAccount().Id
	minted, err := accounts.CreateServiceAccountToken(t.Context(), &nokkuv1.CreateServiceAccountTokenRequest{
		ServiceAccountId: id,
		Label:            new("ci"),
		ExpiresAt:        timestamppb.New(time.Now().Add(time.Hour)),
	})
	require.NoError(t, err)

	machine := clientOn(
		srv, header("Authorization", "Bearer "+minted.GetSecret()),
	)
	_, err = nokkuv1connect.NewServiceAccountServiceClient(machine).UpdateServiceAccount(t.Context(),
		masked(&nokkuv1.UpdateServiceAccountRequest{Id: id, ForceCommand: new(""), SourceAddress: new("")}))
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "lifting its own limits: %v", err)

	authority := nokkuv1connect.NewCertificateServiceClient(machine)
	_, err = authority.UpdateCertificateAuthority(t.Context(),
		masked(&nokkuv1.UpdateCertificateAuthorityRequest{SourceAddress: new("")}))
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "clearing the list of people: %v", err)
	_, err = authority.RolloverCertificateAuthority(t.Context(),
		&nokkuv1.RolloverCertificateAuthorityRequest{RevokePrevious: new(true)})
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "rolling the CA over: %v", err)

	got, err := accounts.GetServiceAccount(t.Context(), &nokkuv1.GetServiceAccountRequest{Id: id})
	require.NoError(t, err)
	assert.Equal(t, "/usr/local/bin/deploy", got.GetServiceAccount().GetForceCommand())

	// A name is no limit, an old sign-in may change it.
	old := clientOn(srv,
		header("Cookie", sessionCookie+"="+browserSession(t, cfg, u, oldSignIn).token))
	oldAccounts := nokkuv1connect.NewServiceAccountServiceClient(old)
	_, err = oldAccounts.UpdateServiceAccount(t.Context(),
		masked(&nokkuv1.UpdateServiceAccountRequest{Id: id, Description: new("changed")}))
	require.NoError(t, err)

	// A field outside the mask asks for nothing, the web app sends them all.
	_, err = oldAccounts.UpdateServiceAccount(t.Context(), &nokkuv1.UpdateServiceAccountRequest{
		Id:           id,
		Description:  new("changed again"),
		ForceCommand: new(""),
		UpdateMask:   &fieldmaskpb.FieldMask{Paths: []string{"description"}},
	})
	require.NoError(t, err)
	got, err = accounts.GetServiceAccount(t.Context(), &nokkuv1.GetServiceAccountRequest{Id: id})
	require.NoError(t, err)
	assert.Equal(t, "changed again", got.GetServiceAccount().GetDescription())
	assert.Equal(
		t,
		"/usr/local/bin/deploy",
		got.GetServiceAccount().GetForceCommand(),
		"a field outside the mask changed",
	)
}

func TestServiceAccountRole(t *testing.T) {
	cfg, srv := newTestAPI(t)
	auth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	client := nokkuv1connect.NewServiceAccountServiceClient(
		clientOn(srv, auth),
	)

	created, err := client.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
		Name: new(uniq("sa")),
	})
	require.NoError(t, err)
	id := created.GetServiceAccount().GetId()
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER, created.GetServiceAccount().GetRole(),
		"no role is the member")

	update := func(role *nokkuv1.WorkspaceRole) (nokkuv1.WorkspaceRole, error) {
		res, err := client.UpdateServiceAccount(
			t.Context(),
			masked(&nokkuv1.UpdateServiceAccountRequest{Id: &id, Role: role}),
		)
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
	err = cfg.Conn.TenantTx(wsCtx(t), func(q *db.Queries) error {
		_, err := q.CreateServiceAccount(t.Context(), &db.CreateServiceAccountParams{
			Name: uniq("sa"),
			Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN,
		})
		return err
	})
	assert.Error(t, err, "the table took a service account above the editor")
}

// serviceAccountToken is a key that ends at expiresAt, or in a month if nil.
func serviceAccountToken(
	t *testing.T,
	client nokkuv1connect.ServiceAccountServiceClient,
	id string,
	expiresAt *timestamppb.Timestamp,
) string {
	t.Helper()
	if expiresAt == nil {
		expiresAt = timestamppb.New(time.Now().AddDate(0, 1, 0))
	}
	res, err := client.CreateServiceAccountToken(t.Context(), &nokkuv1.CreateServiceAccountTokenRequest{
		ServiceAccountId: &id,
		ExpiresAt:        expiresAt,
	})
	require.NoError(t, err)
	return res.GetSecret()
}

// Tokens revoke one by one, so a new one can roll out before the old one goes.
func TestServiceAccountTokens(t *testing.T) {
	cfg, srv := newTestAPI(t)
	auth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	client := nokkuv1connect.NewServiceAccountServiceClient(
		clientOn(srv, auth),
	)

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
	assert.Nil(t, first.GetToken().GetLastUsedAt(), "a new token was never used")
	assert.WithinDuration(t, expiry, first.GetToken().GetExpiresAt().AsTime(), time.Second)
	second, err := client.CreateServiceAccountToken(t.Context(), &nokkuv1.CreateServiceAccountTokenRequest{
		ServiceAccountId: &id,
		ExpiresAt:        timestamppb.New(expiry),
	})
	require.NoError(t, err)
	_, err = client.CreateServiceAccountToken(t.Context(), &nokkuv1.CreateServiceAccountTokenRequest{
		ServiceAccountId: &id,
	})
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "a key with no end date, got %v", err)

	whoami := func(token string) (string, error) {
		res, err := nokkuv1connect.NewTargetServiceClient(clientOn(srv, header("Authorization", "Bearer "+token))).
			GetSubjectAccess(t.Context(), &nokkuv1.GetSubjectAccessRequest{})
		return res.GetServiceAccount().GetId(), err
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
