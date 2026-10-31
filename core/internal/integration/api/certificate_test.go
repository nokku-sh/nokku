//go:build integration

package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// Without a grant nothing is signed. The daemon is handed the very principal the certificate carries.
func TestSignSSHCertificate(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	adminAuth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	seedDefaultCA(t, srv, adminAuth)
	daemonKey, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, false)
	targetID := enrolled.GetTargetId()
	otherID := seedTarget(t, cfg, workspaceID)

	memberToken := seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	member, _, err := cfg.IAM.AuthenticateToken(wsCtx(t, cfg), memberToken, accessTokens...)
	require.NoError(t, err)
	wantPrincipal := member.ID + "@" + targetID + ":root"
	nkToken := cliSessionFor(t, cfg, &db.User{ID: member.ID})

	principals := nokkuv1connect.NewTargetAccountServiceClient(
		connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), adminAuth),
	)
	root, err := principals.AddTargetAccount(t.Context(), &nokkuv1.AddTargetAccountRequest{
		TargetId: &targetID,
		Username: new("root"),
	})
	require.NoError(t, err)
	grant := &nokkuv1.AddSubjectsRequest{
		Id:         new(root.GetAccount().GetId()),
		Kind:       nokkuv1.SubjectKind_SUBJECT_KIND_USER.Enum(),
		SubjectIds: []string{member.ID},
	}
	_, err = principals.AddSubjects(t.Context(), grant)
	require.NoError(t, err)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := gossh.NewPublicKey(pub)
	require.NoError(t, err)
	sign := func(target string) ([]string, error) {
		res, err := nokkuv1connect.NewCertificateServiceClient(connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), header("Authorization", "Bearer "+nkToken))).
			SignSSHCertificate(t.Context(), &nokkuv1.SignSSHCertificateRequest{
				TargetId:  &target,
				PublicKey: new(string(gossh.MarshalAuthorizedKey(sshPub))),
			})
		if err != nil {
			return nil, err
		}
		key, _, _, _, err := gossh.ParseAuthorizedKey([]byte(res.GetSignedCertificate()))
		require.NoError(t, err)
		cert, ok := key.(*gossh.Certificate)
		require.True(t, ok, "the answer is not a certificate")
		return cert.ValidPrincipals, nil
	}

	_, err = sign(targetID)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err),
		"a daemon nobody approved got a certificate signed, %v", err)
	_, err = nokkuv1connect.NewDaemonServiceClient(connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), adminAuth)).
		UpdateDaemon(t.Context(), masked(&nokkuv1.UpdateDaemonRequest{
			Id:     new(enrolled.GetId()),
			Status: nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED.Enum(),
		}))
	require.NoError(t, err)

	signed, err := sign(targetID)
	require.NoError(t, err)
	assert.Equal(t, []string{wantPrincipal}, signed, "the certificate names subject, server and account")

	_, err = sign(otherID)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err),
		"a server without a grant got a certificate signed, %v", err)

	synced, err := nokkuv1connect.NewDaemonControlServiceClient(connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), daemonAuth(t, cfg, daemonKey, enrolled.GetAccessToken(),
		nokkuv1connect.DaemonControlServiceSyncDaemonProcedure))).
		SyncDaemon(t.Context(), &nokkuv1.SyncDaemonRequest{})
	require.NoError(t, err)
	require.Len(t, synced.GetPrincipals(), 1)
	assert.Equal(t, []string{wantPrincipal}, synced.GetPrincipals()[0].GetCertPrincipals(),
		"the daemon must be told the principal the certificate carries")

	_, err = principals.RemoveSubjects(t.Context(), &nokkuv1.RemoveSubjectsRequest{
		Id:         grant.Id,
		Kind:       grant.Kind,
		SubjectIds: grant.GetSubjectIds(),
	})
	require.NoError(t, err)
	_, err = sign(targetID)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err),
		"a revoked grant still got a certificate signed, %v", err)
}

// A service account's certificate lives an hour at most and never past the token it was asked for with.
func TestServiceAccountCertificateLifetime(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	adminAuth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	seedDefaultCA(t, srv, adminAuth)
	_, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	require.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED, enrolled.GetStatus())
	targetID := enrolled.GetTargetId()

	accounts := nokkuv1connect.NewServiceAccountServiceClient(
		connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), adminAuth),
	)
	created, err := accounts.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
		Name: new(uniq("ci")),
	})
	require.NoError(t, err)
	id := created.GetServiceAccount().GetId()
	tokenExpiry := time.Now().Add(10 * time.Minute)
	short := serviceAccountToken(t, accounts, id, timestamppb.New(tokenExpiry))

	principals := nokkuv1connect.NewTargetAccountServiceClient(
		connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), adminAuth),
	)
	root, err := principals.AddTargetAccount(t.Context(), &nokkuv1.AddTargetAccountRequest{
		TargetId: &targetID,
		Username: new("root"),
	})
	require.NoError(t, err)
	_, err = principals.AddSubjects(t.Context(), &nokkuv1.AddSubjectsRequest{
		Id:         new(root.GetAccount().GetId()),
		Kind:       nokkuv1.SubjectKind_SUBJECT_KIND_SERVICE_ACCOUNT.Enum(),
		SubjectIds: []string{id},
	})
	require.NoError(t, err)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := gossh.NewPublicKey(pub)
	require.NoError(t, err)
	// It asks for two days, which the CA would give a person.
	validUntil := func(token string) time.Time {
		res, err := nokkuv1connect.NewCertificateServiceClient(connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), header("Authorization", "Bearer "+token))).
			SignSSHCertificate(t.Context(), &nokkuv1.SignSSHCertificateRequest{
				TargetId:  &targetID,
				PublicKey: new(string(gossh.MarshalAuthorizedKey(sshPub))),
				Ttl:       durationpb.New(48 * time.Hour),
			})
		require.NoError(t, err)
		return res.GetExpiresAt().AsTime()
	}

	assert.False(t, validUntil(short).After(tokenExpiry), "the certificate outlives the token")

	long := serviceAccountToken(t, accounts, id, nil)
	assert.WithinDuration(t, time.Now().Add(time.Hour), validUntil(long), time.Minute,
		"a token that never expires gets the hour, the cap follows the token and not the account")
}

// A CA stores its source addresses the way a server reads them, and refuses a list no server can read.
func TestCARestrictions(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	admin := nokkuv1connect.NewCertificateServiceClient(
		connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), header(
			"Authorization",
			"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
		)),
	)

	created, err := admin.CreateCertificateAuthority(t.Context(), &nokkuv1.CreateCertificateAuthorityRequest{
		Name:          new(uniq("restricted")),
		ForceCommand:  new(" /usr/local/bin/backup "),
		SourceAddress: new("10.0.0.0/8, 192.0.2.7"),
	})
	require.NoError(t, err)
	ca := created.GetCertificateAuthority()
	assert.Equal(t, "/usr/local/bin/backup", ca.GetForceCommand())
	assert.Equal(t, "10.0.0.0/8,192.0.2.7", ca.GetSourceAddress())

	_, err = admin.UpdateCertificateAuthority(t.Context(), masked(&nokkuv1.UpdateCertificateAuthorityRequest{
		Id: ca.Id, SourceAddress: new("the office"),
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "got %v", err)

	// An update that names neither keeps both, an empty one takes the restriction away.
	renamed, err := admin.UpdateCertificateAuthority(t.Context(), masked(&nokkuv1.UpdateCertificateAuthorityRequest{
		Id: ca.Id, Name: new(uniq("renamed")),
	}))
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.0/8,192.0.2.7", renamed.GetCertificateAuthority().GetSourceAddress())
	cleared, err := admin.UpdateCertificateAuthority(t.Context(), masked(&nokkuv1.UpdateCertificateAuthorityRequest{
		Id: ca.Id, SourceAddress: new(""),
	}))
	require.NoError(t, err)
	assert.Empty(t, cleared.GetCertificateAuthority().GetSourceAddress())
	assert.Equal(t, "/usr/local/bin/backup", cleared.GetCertificateAuthority().GetForceCommand())
}

// The default moves in both directions. One statement that swaps it depends on which row Postgres visits first.
func TestDefaultCAMoves(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	adminAuth := header("Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN))
	admin := nokkuv1connect.NewCertificateServiceClient(
		connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), adminAuth),
	)
	defaults := func() []string {
		res, err := admin.ListCertificateAuthorities(t.Context(), &nokkuv1.ListCertificateAuthoritiesRequest{})
		require.NoError(t, err)
		var ids []string
		for _, ca := range res.GetCertificateAuthorities() {
			if ca.GetIsDefault() {
				ids = append(ids, ca.GetId())
			}
		}
		return ids
	}

	first := seedDefaultCA(t, srv, adminAuth).GetId()
	second := seedDefaultCA(t, srv, adminAuth).GetId()
	assert.Equal(t, []string{second}, defaults(), "a new default takes it from the old one")

	_, err := admin.UpdateCertificateAuthority(t.Context(), masked(&nokkuv1.UpdateCertificateAuthorityRequest{
		Id: &first, IsDefault: new(true),
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{first}, defaults(), "the default moves back to an older CA")
}

// A server made without a CA gets the default. The default, and a CA a server still uses, cannot be deleted.
func TestDeleteCAInUse(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	adminAuth := header("Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN))
	client := connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), adminAuth)
	certs := nokkuv1connect.NewCertificateServiceClient(client)
	targets := nokkuv1connect.NewTargetServiceClient(client)
	deleteCA := func(id string) error {
		_, err := certs.DeleteCertificateAuthority(t.Context(), &nokkuv1.DeleteCertificateAuthorityRequest{Id: &id})
		return err
	}

	defaultID := seedDefaultCA(t, srv, adminAuth).GetId()
	created, err := targets.CreateTarget(t.Context(), &nokkuv1.CreateTargetRequest{Name: new(uniq("no-ca"))})
	require.NoError(t, err)
	target := created.GetTarget()
	assert.Equal(t, defaultID, target.GetCaId(), "a server made without a CA gets the default")
	require.ErrorContains(t, deleteCA(defaultID), "the default", "the default stays")

	other, err := certs.CreateCertificateAuthority(t.Context(), &nokkuv1.CreateCertificateAuthorityRequest{
		Name: new(uniq("other")),
	})
	require.NoError(t, err)
	otherID := other.GetCertificateAuthority().GetId()
	_, err = targets.UpdateTarget(t.Context(), masked(&nokkuv1.UpdateTargetRequest{Id: target.Id, CaId: &otherID}))
	require.NoError(t, err)
	err = deleteCA(otherID)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
	require.ErrorContains(t, err, "servers still use", "a CA a server uses stays")

	_, err = targets.DeleteTarget(t.Context(), &nokkuv1.DeleteTargetRequest{Id: target.Id})
	require.NoError(t, err)
	assert.NoError(t, deleteCA(otherID), "a CA no server uses goes")
}
