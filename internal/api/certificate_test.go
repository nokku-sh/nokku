package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/db"
)

// The subject and SANs are copied from the CSR, so signing is as powerful as
// holding the CA. Only the roles that manage CAs may do it.
func TestSignX509NeedsEditor(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	client := func(role db.Role) nokkuv1connect.CertificateServiceClient {
		return nokkuv1connect.NewCertificateServiceClient(srv.Client(), srv.URL,
			header("Authorization", "Bearer "+seedMember(t, cfg, workspaceID, role)))
	}

	ca, err := client(db.RoleEditor).CreateCertificateAuthority(t.Context(), &nokkuv1.CreateCertificateAuthorityRequest{
		WorkspaceId:   &workspaceID,
		Name:          new("x509"),
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
		WorkspaceId: &workspaceID,
		CaId:        new(ca.GetCertificateAuthority().GetId()),
		Csr:         new(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))),
	}

	for _, role := range []db.Role{db.RoleMember, db.RoleViewer} {
		_, err = client(role).SignX509Certificate(t.Context(), req)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "%s signed a certificate, got %v", role, err)
	}

	res, err := client(db.RoleEditor).SignX509Certificate(t.Context(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, res.GetCertificate())
}
