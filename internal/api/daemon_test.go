package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
)

// enrollProof signs a DPoP proof for EnrollDaemon the way nokkud does.
func enrollProof(t *testing.T, cfg *config.Config, key *ecdsa.PrivateKey) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"htm":   http.MethodPost,
		"htu":   cfg.FullURL() + nokkuv1connect.DaemonServiceEnrollDaemonProcedure,
		"iat":   time.Now().Unix(),
		"jti":   rand.Text(),
		"nonce": cfg.IAM.DPoP.CurrentNonce(),
	})
	require.NoError(t, err)
	opts := (&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: cryptosigner.Opaque(key)}, opts)
	require.NoError(t, err)
	jws, err := signer.Sign(payload)
	require.NoError(t, err)
	proof, err := jws.CompactSerialize()
	require.NoError(t, err)
	return proof
}

func TestEnrollDaemon(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	adminAuth := header("Authorization", "Bearer "+seedMember(t, cfg, workspaceID, db.RoleAdmin))

	created, err := nokkuv1connect.NewTokenServiceClient(srv.Client(), srv.URL, adminAuth).
		CreateToken(t.Context(), &nokkuv1.CreateTokenRequest{
			WorkspaceId: &workspaceID,
			Kind:        nokkuv1.TokenKind_TOKEN_KIND_ENROLL.Enum(),
			MaxUses:     new(int32(1)),
			AutoApprove: new(true),
		})
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	enroll := func(token string, key *ecdsa.PrivateKey) (*nokkuv1.EnrollDaemonResponse, error) {
		client := nokkuv1connect.NewDaemonServiceClient(srv.Client(), srv.URL, header("DPoP", enrollProof(t, cfg, key)))
		return client.EnrollDaemon(t.Context(), &nokkuv1.EnrollDaemonRequest{Token: &token})
	}

	res, err := enroll(created.GetSecret(), key)
	require.NoError(t, err)
	assert.Equal(t, workspaceID, res.GetWorkspaceId())
	assert.NotEmpty(t, res.GetTargetId(), "enrollment creates the target")
	assert.NotEmpty(t, res.GetAccessToken())
	assert.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED, res.GetStatus(), "auto approve token")

	got, err := nokkuv1connect.NewDaemonServiceClient(srv.Client(), srv.URL, adminAuth).
		GetDaemon(t.Context(), &nokkuv1.GetDaemonRequest{WorkspaceId: &workspaceID, Id: new(res.GetId())})
	require.NoError(t, err)
	assert.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED, got.GetDaemon().GetStatus())

	// The same key enrolls into the same daemon, even with the token used up.
	again, err := enroll(created.GetSecret(), key)
	require.NoError(t, err)
	assert.Equal(t, res.GetId(), again.GetId())

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = enroll(created.GetSecret(), otherKey)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err), "used up token, got %v", err)
	_, err = enroll("nk_not-a-token", otherKey)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err), "bad token, got %v", err)
}

// TestCreateSession stops short of a live session: no daemon holds a control
// stream here, so a member gets Unavailable after every lookup succeeded.
func TestCreateSession(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	adminAuth := header("Authorization", "Bearer "+seedMember(t, cfg, workspaceID, db.RoleAdmin))

	// Enrollment falls back to the default CA, which CreateSession needs.
	_, err := nokkuv1connect.NewCertificateServiceClient(srv.Client(), srv.URL, adminAuth).
		CreateCertificateAuthority(t.Context(), &nokkuv1.CreateCertificateAuthorityRequest{
			WorkspaceId: &workspaceID,
			Name:        new("default"),
			KeyType:     nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519.Enum(),
			IsDefault:   new(true),
		})
	require.NoError(t, err)
	created, err := nokkuv1connect.NewTokenServiceClient(srv.Client(), srv.URL, adminAuth).
		CreateToken(t.Context(), &nokkuv1.CreateTokenRequest{
			WorkspaceId: &workspaceID,
			Kind:        nokkuv1.TokenKind_TOKEN_KIND_ENROLL.Enum(),
			AutoApprove: new(true),
		})
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	enrolled, err := nokkuv1connect.NewDaemonServiceClient(srv.Client(), srv.URL, header("DPoP", enrollProof(t, cfg, key))).
		EnrollDaemon(t.Context(), &nokkuv1.EnrollDaemonRequest{Token: new(created.GetSecret())})
	require.NoError(t, err)

	req := &nokkuv1.CreateSessionRequest{
		WorkspaceId: &workspaceID,
		DaemonId:    new(enrolled.GetId()),
		Username:    new("root"),
	}
	member := nokkuv1connect.NewDaemonServiceClient(srv.Client(), srv.URL,
		header("Authorization", "Bearer "+seedMember(t, cfg, workspaceID, db.RoleMember)))
	_, err = member.CreateSession(t.Context(), req)
	assert.Equal(t, connect.CodeUnavailable, connect.CodeOf(err), "offline daemon, got %v", err)

	sa, err := nokkuv1connect.NewServiceAccountServiceClient(srv.Client(), srv.URL, adminAuth).
		CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
			WorkspaceId: &workspaceID,
			Name:        new("ci"),
			RoleName:    new(string(db.RoleEditor)),
		})
	require.NoError(t, err)
	machine := nokkuv1connect.NewDaemonServiceClient(srv.Client(), srv.URL,
		header("Authorization", "Bearer "+sa.GetToken()))
	_, err = machine.CreateSession(t.Context(), req)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "service account, got %v", err)
}
