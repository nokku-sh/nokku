package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect"
	"github.com/coder/websocket"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
	"github.com/nokku-sh/nokku/internal/sshclient/sshtest"
)

// dpopProof signs a proof the way nokkud does. Session proofs carry the
// access token hash, the enrollment proof has no token yet.
func dpopProof(t *testing.T, cfg *config.Config, key *ecdsa.PrivateKey, procedure, token string) string {
	t.Helper()
	claims := map[string]any{
		"htm":   http.MethodPost,
		"htu":   cfg.FullURL() + procedure,
		"iat":   time.Now().Unix(),
		"jti":   rand.Text(),
		"nonce": cfg.IAM.DPoP.CurrentNonce(),
	}
	if token != "" {
		claims["ath"] = iam.DPoPATH(token)
	}
	payload, err := json.Marshal(claims)
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
		client := nokkuv1connect.NewDaemonServiceClient(
			srv.Client(),
			srv.URL,
			header("DPoP", dpopProof(t, cfg, key, nokkuv1connect.DaemonServiceEnrollDaemonProcedure, "")),
		)
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
	enrollAuth := header("DPoP", dpopProof(t, cfg, key, nokkuv1connect.DaemonServiceEnrollDaemonProcedure, ""))
	enrolled, err := nokkuv1connect.NewDaemonServiceClient(srv.Client(), srv.URL, enrollAuth).
		EnrollDaemon(t.Context(), &nokkuv1.EnrollDaemonRequest{Token: new(created.GetSecret())})
	require.NoError(t, err)

	req := &nokkuv1.CreateSessionRequest{
		WorkspaceId: &workspaceID,
		DaemonId:    new(enrolled.GetId()),
		Username:    new("root"),
	}
	memberToken := seedMember(t, cfg, workspaceID, db.RoleMember)
	member := nokkuv1connect.NewDaemonServiceClient(
		srv.Client(),
		srv.URL,
		header("Authorization", "Bearer "+memberToken),
	)
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

	// The target trusts the sshtest CA, which admits the member's cert.
	memberPrincipal, _, err := cfg.IAM.AuthenticateToken(t.Context(), memberToken)
	require.NoError(t, err)
	sshd := sshtest.NewServerFor(t, enrolled.GetTargetId(), memberPrincipal.ID)
	ca := sshd.CA(t)
	require.NoError(t, cfg.Conn.WithTx(t.Context(), func(q *db.Queries) error {
		row, err := q.CreateCA(t.Context(), &db.CreateCAParams{
			WorkspaceID:    workspaceID,
			Name:           "sshtest",
			Certificate:    ca.PublicKey,
			PrivateKey:     ca.PrivateKey,
			PublicKey:      ca.PublicKey,
			SerialNumber:   uuid.New().String(),
			Subject:        "sshtest",
			NotBefore:      time.Now().Add(-time.Minute),
			NotAfter:       time.Now().Add(time.Hour),
			Lifetime:       time.Hour,
			UserDefaultTtl: ca.UserDefaultTtl,
			UserMaxTtl:     ca.UserMaxTtl,
			UserExtensions: ca.UserExtensions,
		})
		if err != nil {
			return err
		}
		_, err = q.UpdateTargetCA(t.Context(), &db.UpdateTargetCAParams{DaemonID: new(enrolled.GetId()), CaID: &row.ID})
		return err
	}))

	// openShell trades a fresh ticket for the terminal websocket.
	openShell := func() (string, *websocket.Conn) {
		res, err := member.CreateSession(t.Context(), req)
		require.NoError(t, err)
		assert.Equal(t, memberPrincipal.ID, res.GetSession().GetUserId())
		ws, _, err := websocket.Dial(
			t.Context(),
			srv.URL+"/terminal/ws?session_id="+res.GetSession().GetSessionId(),
			&websocket.DialOptions{
				HTTPClient: srv.Client(),
				HTTPHeader: http.Header{"Cookie": {"nokku_session=" + memberToken}},
			},
		)
		require.NoError(t, err)
		return res.GetSession().GetSessionId(), ws
	}

	_, ws := openShell()
	_, _, err = ws.Read(t.Context())
	assert.Equal(t, websocket.StatusInternalError, websocket.CloseStatus(err), "offline daemon, got %v", err)

	// A fake daemon holds the control stream and bridges the relay to sshd.
	token := enrolled.GetAccessToken()
	controlCtx, control := connect.NewClientContext(t.Context())
	control.RequestHeader().Set("Authorization", "DPoP "+token)
	control.RequestHeader().Set("DPoP",
		dpopProof(t, cfg, key, nokkuv1connect.DaemonControlServiceConnectProcedure, token))
	stream, err := nokkuv1connect.NewDaemonControlServiceClient(srv.Client(), srv.URL).Connect(controlCtx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&nokkuv1.ConnectRequest{
		Msg: &nokkuv1.ConnectRequest_Heartbeat{Heartbeat: &nokkuv1.Heartbeat{}},
	}))
	// Signed here since require must not run on the daemon goroutine.
	relayProof := dpopProof(t, cfg, key, nokkuv1connect.DaemonSessionServiceDaemonRelayProcedure, token)
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				return
			}
			relayID := msg.GetRelayOpen().GetRelayId()
			if relayID == "" {
				continue
			}
			conn, err := new(net.Dialer).DialContext(t.Context(), "tcp", sshd.Addr())
			if err != nil {
				return
			}
			relayCtx, info := connect.NewClientContext(t.Context())
			info.RequestHeader().Set("Authorization", "DPoP "+token)
			info.RequestHeader().Set("DPoP", relayProof)
			relay, err := nokkuv1connect.NewDaemonSessionServiceClient(srv.Client(), srv.URL).DaemonRelay(relayCtx)
			if err != nil {
				return
			}
			_ = relay.Send(&nokkuv1.DaemonRelayRequest{
				Msg: &nokkuv1.DaemonRelayRequest_Ready{Ready: &nokkuv1.DaemonRelayReady{RelayId: &relayID}},
			})
			go func() {
				buf := make([]byte, 32*1024)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						_ = relay.Send(
							&nokkuv1.DaemonRelayRequest{Msg: &nokkuv1.DaemonRelayRequest_Data{Data: buf[:n]}},
						)
					}
					if err != nil {
						return
					}
				}
			}()
			go func() {
				defer func() { _ = conn.Close() }()
				for {
					res, err := relay.Receive()
					if err != nil {
						return
					}
					if _, err := conn.Write(res.GetData()); err != nil {
						return
					}
				}
			}()
		}
	}()

	// The dial fails until the pool has registered the control stream.
	var sessionID string
	deadline := time.Now().Add(5 * time.Second)
	for {
		sessionID, ws = openShell()
		// The test sshd echoes stdin, a failed dial closes the socket instead.
		_ = ws.Write(t.Context(), websocket.MessageBinary, []byte("ping\n"))
		readCtx, stop := context.WithTimeout(t.Context(), 3*time.Second)
		_, _, err = ws.Read(readCtx)
		stop()
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.NoError(t, err, "shell output never arrived")
	assert.Equal(t, "root", sshd.ConnUser(), "sshd saw the requested OS user")
	assert.Equal(t, sessionID, sshd.Env("NOKKU_SESSION_ID"), "session env reached sshd")
	assert.Len(t, cfg.Pool.ListSessions(enrolled.GetId()), 1)

	_, res, err := websocket.Dial(t.Context(), srv.URL+"/terminal/ws?session_id="+sessionID,
		&websocket.DialOptions{
			HTTPClient: srv.Client(),
			HTTPHeader: http.Header{"Cookie": {"nokku_session=" + memberToken}},
		})
	require.Error(t, err, "a ticket opens one socket")
	assert.Equal(t, http.StatusNotFound, res.StatusCode)

	// The shell belongs to the socket, closing it is the whole cleanup.
	require.NoError(t, ws.CloseNow())
	assert.Eventually(t, func() bool {
		return len(cfg.Pool.ListSessions(enrolled.GetId())) == 0
	}, 5*time.Second, 20*time.Millisecond, "session outlived its socket")
}
