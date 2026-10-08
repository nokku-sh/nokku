package api

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"
)

// A user certificate is signed for one server and names the accounts the
// caller is granted there. Without a grant nothing is signed, so a revoke
// ends with the last certificate even on a host that never hears of it. The
// daemon and nk sync are handed the very same principals.
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
	member, _, err := cfg.IAM.AuthenticateToken(wsCtx(t, cfg), memberToken)
	require.NoError(t, err)
	wantPrincipal := member.ID + "@" + targetID + ":root"

	principals := nokkuv1connect.NewPrincipalServiceClient(srv.Client(), srv.URL, adminAuth)
	root, err := principals.AddPrincipal(t.Context(), &nokkuv1.AddPrincipalRequest{
		TargetId: &targetID,
		Username: new("root"),
	})
	require.NoError(t, err)
	grant := &nokkuv1.AddSubjectsToPrincipalRequest{
		Id:         new(root.GetPrincipal().GetId()),
		Kind:       nokkuv1.SubjectKind_SUBJECT_KIND_USER.Enum(),
		SubjectIds: []string{member.ID},
	}
	_, err = principals.AddSubjectsToPrincipal(t.Context(), grant)
	require.NoError(t, err)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := gossh.NewPublicKey(pub)
	require.NoError(t, err)
	sign := func(target string) ([]string, error) {
		res, err := nokkuv1connect.NewCertificateServiceClient(
			srv.Client(), srv.URL, header("Authorization", "Bearer "+memberToken),
		).SignSSHCertificate(t.Context(), &nokkuv1.SignSSHCertificateRequest{
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
	_, err = nokkuv1connect.NewDaemonServiceClient(srv.Client(), srv.URL, adminAuth).
		UpdateDaemon(t.Context(), &nokkuv1.UpdateDaemonRequest{
			Id:     new(enrolled.GetId()),
			Status: nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED.Enum(),
		})
	require.NoError(t, err)

	signed, err := sign(targetID)
	require.NoError(t, err)
	assert.Equal(t, []string{wantPrincipal}, signed, "the certificate names subject, server and account")

	_, err = sign(otherID)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err),
		"a server without a grant got a certificate signed, %v", err)

	synced, err := nokkuv1connect.NewDaemonControlServiceClient(srv.Client(), srv.URL,
		daemonAuth(t, cfg, daemonKey, enrolled.GetAccessToken(),
			nokkuv1connect.DaemonControlServiceSyncDaemonProcedure)).
		SyncDaemon(t.Context(), &nokkuv1.SyncDaemonRequest{})
	require.NoError(t, err)
	require.Len(t, synced.GetPrincipals(), 1)
	assert.Equal(t, []string{wantPrincipal}, synced.GetPrincipals()[0].GetCertPrincipals(),
		"the daemon must be told the principal the certificate carries")

	listed, err := nokkuv1connect.NewTargetServiceClient(srv.Client(), srv.URL, adminAuth).
		GetTargetPrincipals(t.Context(), &nokkuv1.GetTargetPrincipalsRequest{
			TargetId: &targetID,
		})
	require.NoError(t, err)
	require.Len(t, listed.GetPrincipals(), 1)
	assert.Equal(t, []string{wantPrincipal}, listed.GetPrincipals()[0].GetCertPrincipals(),
		"nk sync must write the principal the certificate carries")

	_, err = principals.RemoveSubjectsFromPrincipal(t.Context(), &nokkuv1.RemoveSubjectsFromPrincipalRequest{
		Id:         grant.Id,
		Kind:       grant.Kind,
		SubjectIds: grant.GetSubjectIds(),
	})
	require.NoError(t, err)
	_, err = sign(targetID)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err),
		"a revoked grant still got a certificate signed, %v", err)
}

// The subject and SANs are copied from the CSR, so signing is as powerful as
// holding the CA. Only the roles that manage CAs may do it.
func TestSignX509NeedsEditor(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	client := func(role nokkuv1.WorkspaceRole) nokkuv1connect.CertificateServiceClient {
		return nokkuv1connect.NewCertificateServiceClient(srv.Client(), srv.URL,
			header("Authorization", "Bearer "+seedMember(t, cfg, workspaceID, role)))
	}

	ca, err := client(
		nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR,
	).CreateCertificateAuthority(t.Context(), &nokkuv1.CreateCertificateAuthorityRequest{
		Name:          new(uniq("x509")),
		KeyType:       nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ECDSA.Enum(),
		AuthorityType: nokkuv1.AuthorityType_AUTHORITY_TYPE_X509.Enum(),
	})
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "admin", Organization: []string{"system:masters"}},
		DNSNames: []string{"kube.internal"},
	}, key)
	require.NoError(t, err)
	req := &nokkuv1.SignX509CertificateRequest{
		CaId: new(ca.GetCertificateAuthority().GetId()),
		Csr:  new(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))),
	}

	for _, role := range []nokkuv1.WorkspaceRole{nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER} {
		_, err = client(role).SignX509Certificate(t.Context(), req)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "%s signed a certificate, got %v", role, err)
	}

	res, err := client(nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR).SignX509Certificate(t.Context(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, res.GetCertificate())
}
