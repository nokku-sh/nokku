package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect"
	"github.com/coder/websocket"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"

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
		client := nokkuv1connect.NewDaemonControlServiceClient(
			srv.Client(),
			srv.URL,
			header("DPoP", dpopProof(t, cfg, key, nokkuv1connect.DaemonControlServiceEnrollDaemonProcedure, "")),
		)
		return client.EnrollDaemon(t.Context(), &nokkuv1.EnrollDaemonRequest{Token: &token})
	}

	res, err := enroll(created.GetSecret(), key)
	require.NoError(t, err)
	assert.Equal(t, workspaceID, res.GetWorkspaceId())
	assert.NotEmpty(t, res.GetTargetId(), "enrollment creates the target")
	assert.NotEmpty(t, res.GetAccessToken())
	assert.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED, res.GetStatus(), "auto approve token")

	daemons := nokkuv1connect.NewDaemonServiceClient(srv.Client(), srv.URL, adminAuth)
	got, err := daemons.GetDaemon(
		t.Context(),
		&nokkuv1.GetDaemonRequest{WorkspaceId: &workspaceID, Id: new(res.GetId())},
	)
	require.NoError(t, err)
	assert.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED, got.GetDaemon().GetStatus())

	// The workspace has no defaults of its own, so the built-in ones apply and
	// the daemon and the API agree on every field.
	assert.True(t, proto.Equal(db.DefaultDaemonConfig(), res.GetConfig()),
		"enroll answers with a complete config, got %v", res.GetConfig())
	assert.True(t, proto.Equal(db.DefaultDaemonConfig(), got.GetDaemon().GetConfig()),
		"the API reads the same config back, got %v", got.GetDaemon().GetConfig())

	// One switch off keeps the others where they were.
	_, err = daemons.UpdateDaemon(t.Context(), &nokkuv1.UpdateDaemonRequest{
		WorkspaceId: &workspaceID,
		Id:          new(res.GetId()),
		Config:      &nokkuv1.DaemonConfig{RecordSessions: new(false)},
	})
	require.NoError(t, err)
	got, err = daemons.GetDaemon(
		t.Context(),
		&nokkuv1.GetDaemonRequest{WorkspaceId: &workspaceID, Id: new(res.GetId())},
	)
	require.NoError(t, err)
	want := db.DefaultDaemonConfig()
	want.RecordSessions = new(false)
	assert.True(t, proto.Equal(want, got.GetDaemon().GetConfig()),
		"an explicit off survives, unset fields read as the defaults, got %v", got.GetDaemon().GetConfig())
	assert.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED, got.GetDaemon().GetStatus(),
		"a config change leaves the status alone")

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
	enrollAuth := header("DPoP", dpopProof(t, cfg, key, nokkuv1connect.DaemonControlServiceEnrollDaemonProcedure, ""))
	enrolled, err := nokkuv1connect.NewDaemonControlServiceClient(srv.Client(), srv.URL, enrollAuth).
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

	memberPrincipal, _, err := cfg.IAM.AuthenticateToken(t.Context(), memberToken)
	require.NoError(t, err)

	// Membership alone opens nothing. A web shell and a relay need a grant on
	// the target, like sshd asks for.
	openRelay := func() error {
		relayCtx, info := connect.NewClientContext(t.Context())
		info.RequestHeader().Set("Authorization", "Bearer "+memberToken)
		relay, err := nokkuv1connect.NewDaemonServiceClient(srv.Client(), srv.URL).Relay(relayCtx)
		if err != nil {
			return err
		}
		if err := relay.Send(&nokkuv1.RelayRequest{Msg: &nokkuv1.RelayRequest_Start{
			Start: &nokkuv1.RelayStart{WorkspaceId: &workspaceID, DaemonId: new(enrolled.GetId())},
		}}); err != nil {
			return err
		}
		_, err = relay.Receive()
		return err
	}
	_, err = member.CreateSession(t.Context(), req)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "web session without a grant, got %v", err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(openRelay()), "relay without a grant")

	require.NoError(t, cfg.Conn.WithTx(t.Context(), func(q *db.Queries) error {
		p, err := q.CreatePrincipal(t.Context(), &db.CreatePrincipalParams{
			WorkspaceID: workspaceID, TargetID: enrolled.GetTargetId(), Username: "root",
		})
		if err != nil {
			return err
		}
		return q.AddPrincipalGrant(t.Context(), &db.AddPrincipalGrantParams{
			PrincipalID: p.ID, WorkspaceID: workspaceID, SubjectKind: "user", SubjectID: memberPrincipal.ID,
		})
	}))
	// With the grant the relay gets past the check, the daemon is just offline.
	assert.Equal(t, connect.CodeUnavailable, connect.CodeOf(openRelay()), "relay with a grant")
	_, err = member.CreateSession(t.Context(), &nokkuv1.CreateSessionRequest{
		WorkspaceId: &workspaceID,
		DaemonId:    new(enrolled.GetId()),
		Username:    new("postgres"),
	})
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "another account on the host, got %v", err)

	// The target trusts the sshtest CA, which admits the member's cert.
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
	// Signed here since require must not run on the daemon goroutine. A proof
	// is single use, so every relay takes its own.
	relayProofs := make(chan string, 3)
	for range cap(relayProofs) {
		relayProofs <- dpopProof(t, cfg, key, nokkuv1connect.DaemonControlServiceDaemonRelayProcedure, token)
	}
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
			select {
			case proof := <-relayProofs:
				info.RequestHeader().Set("DPoP", proof)
			case <-t.Context().Done():
				return
			}
			relay, err := nokkuv1connect.NewDaemonControlServiceClient(srv.Client(), srv.URL).DaemonRelay(relayCtx)
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

	// Ctrl+D ends the shell, and the socket says so with its own close code.
	_, ws = openShell()
	require.NoError(t, ws.Write(t.Context(), websocket.MessageBinary, []byte{0x04}))
	readCtx, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	for err = nil; err == nil; {
		_, _, err = ws.Read(readCtx)
	}
	assert.Equal(t, wsShellExited, websocket.CloseStatus(err), "shell exit, got %v", err)
	assert.Eventually(t, func() bool {
		return len(cfg.Pool.ListSessions(enrolled.GetId())) == 0
	}, 5*time.Second, 20*time.Millisecond, "session outlived its shell")
}

// daemonAuth signs one call the way nokkud does.
func daemonAuth(t *testing.T, cfg *config.Config, key *ecdsa.PrivateKey, token, procedure string) connect.ClientOption {
	t.Helper()
	return connect.WithClientOptions(
		header("Authorization", "DPoP "+token),
		header("DPoP", dpopProof(t, cfg, key, procedure, token)),
	)
}

func enrollTestDaemon(
	t *testing.T,
	cfg *config.Config,
	srv *httptest.Server,
	workspaceID string,
	autoApprove bool,
) (*ecdsa.PrivateKey, *nokkuv1.EnrollDaemonResponse) {
	t.Helper()
	adminAuth := header("Authorization", "Bearer "+seedMember(t, cfg, workspaceID, db.RoleAdmin))
	created, err := nokkuv1connect.NewTokenServiceClient(srv.Client(), srv.URL, adminAuth).
		CreateToken(t.Context(), &nokkuv1.CreateTokenRequest{
			WorkspaceId: &workspaceID,
			Kind:        nokkuv1.TokenKind_TOKEN_KIND_ENROLL.Enum(),
			AutoApprove: &autoApprove,
		})
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	enrollAuth := header("DPoP", dpopProof(t, cfg, key, nokkuv1connect.DaemonControlServiceEnrollDaemonProcedure, ""))
	enrolled, err := nokkuv1connect.NewDaemonControlServiceClient(srv.Client(), srv.URL, enrollAuth).
		EnrollDaemon(t.Context(), &nokkuv1.EnrollDaemonRequest{Token: new(created.GetSecret())})
	require.NoError(t, err)
	return key, enrolled
}

// A daemon nobody approved may ask for its status and nothing else.
func TestPendingDaemonIsDenied(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, false)
	require.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING, enrolled.GetStatus())
	token := enrolled.GetAccessToken()

	synced, err := nokkuv1connect.NewDaemonControlServiceClient(srv.Client(), srv.URL,
		daemonAuth(t, cfg, key, token, nokkuv1connect.DaemonControlServiceSyncDaemonProcedure)).
		SyncDaemon(t.Context(), &nokkuv1.SyncDaemonRequest{})
	require.NoError(t, err)
	assert.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING, synced.GetStatus())
	assert.Empty(t, synced.GetPrincipals())

	_, err = nokkuv1connect.NewDaemonControlServiceClient(srv.Client(), srv.URL,
		daemonAuth(t, cfg, key, token, nokkuv1connect.DaemonControlServiceSignHostCertificateProcedure)).
		SignHostCertificate(t.Context(), &nokkuv1.SignHostCertificateRequest{PublicKey: new("ssh-ed25519 AAAA")})
	assert.Equal(
		t,
		connect.CodePermissionDenied,
		connect.CodeOf(err),
		"pending daemon reached the handler, got %v",
		err,
	)
}

// A deleted daemon is told to stop, so its host drops the cached principals.
func TestDeletedDaemonIsRejected(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	token := enrolled.GetAccessToken()

	adminAuth := header("Authorization", "Bearer "+seedMember(t, cfg, workspaceID, db.RoleAdmin))
	_, err := nokkuv1connect.NewDaemonServiceClient(srv.Client(), srv.URL, adminAuth).
		DeleteDaemon(t.Context(), &nokkuv1.DeleteDaemonRequest{WorkspaceId: &workspaceID, Id: new(enrolled.GetId())})
	require.NoError(t, err)

	sync := func() (*nokkuv1.SyncDaemonResponse, error) {
		return nokkuv1connect.NewDaemonControlServiceClient(srv.Client(), srv.URL,
			daemonAuth(t, cfg, key, token, nokkuv1connect.DaemonControlServiceSyncDaemonProcedure)).
			SyncDaemon(t.Context(), &nokkuv1.SyncDaemonRequest{})
	}
	synced, err := sync()
	require.NoError(t, err)
	assert.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_REJECTED, synced.GetStatus())

	_, err = sync()
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "the session outlived the daemon, got %v", err)
}

// seedDefaultCA gives the workspace the CA an enrollment falls back to.
func seedDefaultCA(t *testing.T, srv *httptest.Server, adminAuth connect.ClientOption, workspaceID string) string {
	t.Helper()
	created, err := nokkuv1connect.NewCertificateServiceClient(srv.Client(), srv.URL, adminAuth).
		CreateCertificateAuthority(t.Context(), &nokkuv1.CreateCertificateAuthorityRequest{
			WorkspaceId: &workspaceID,
			Name:        new("default"),
			KeyType:     nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519.Enum(),
			IsDefault:   new(true),
		})
	require.NoError(t, err)
	return created.GetCertificateAuthority().GetPublicKey()
}

// The report is a hint from the host. What does not parse is dropped and the
// rest still lands, so one odd account never blocks a sync.
func TestSyncDaemonReport(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	adminAuth := header("Authorization", "Bearer "+seedMember(t, cfg, workspaceID, db.RoleAdmin))
	caKey := seedDefaultCA(t, srv, adminAuth, workspaceID)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	token := enrolled.GetAccessToken()

	synced, err := nokkuv1connect.NewDaemonControlServiceClient(srv.Client(), srv.URL,
		daemonAuth(t, cfg, key, token, nokkuv1connect.DaemonControlServiceSyncDaemonProcedure)).
		SyncDaemon(t.Context(), &nokkuv1.SyncDaemonRequest{
			Users:      []string{"root", "deploy", "bad name", `corp\john`},
			PrivateIps: []string{"10.0.0.5:4022", "example.com:22", "nonsense"},
		})
	require.NoError(t, err)
	assert.Equal(t, caKey, synced.GetCaPublicKey(), "the daemon trusts the CA of its target")
	assert.True(t, proto.Equal(db.DefaultDaemonConfig(), synced.GetConfig()),
		"the daemon is told every setting, got %v", synced.GetConfig())

	var usernames, endpoints []string
	require.NoError(t, cfg.Conn.WithTx(t.Context(), func(q *db.Queries) error {
		target, err := q.GetTargetByDaemon(t.Context(), new(enrolled.GetId()))
		if err != nil {
			return err
		}
		endpoints = target.Endpoints
		rows, err := q.GetPrincipalsByTargetIDs(t.Context(), []string{target.ID})
		for _, r := range rows {
			usernames = append(usernames, r.Principal.Username)
		}
		return err
	}))
	assert.Equal(t, []string{"deploy", "root"}, usernames)
	assert.Equal(t, []string{"10.0.0.5:4022"}, endpoints)
}

func TestSignHostCertificate(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	adminAuth := header("Authorization", "Bearer "+seedMember(t, cfg, workspaceID, db.RoleAdmin))
	caKey := seedDefaultCA(t, srv, adminAuth, workspaceID)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)

	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	hostPub, err := ssh.NewPublicKey(&hostKey.PublicKey)
	require.NoError(t, err)

	res, err := nokkuv1connect.NewDaemonControlServiceClient(srv.Client(), srv.URL,
		daemonAuth(
			t, cfg, key, enrolled.GetAccessToken(),
			nokkuv1connect.DaemonControlServiceSignHostCertificateProcedure,
		)).
		SignHostCertificate(t.Context(), &nokkuv1.SignHostCertificateRequest{
			PublicKey: new(string(ssh.MarshalAuthorizedKey(hostPub))),
		})
	require.NoError(t, err)

	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(res.GetSignedCertificate()))
	require.NoError(t, err)
	cert, ok := parsed.(*ssh.Certificate)
	require.True(t, ok, "not a certificate")
	assert.Equal(t, uint32(ssh.HostCert), cert.CertType)
	assert.Equal(t, []string{enrolled.GetTargetId()}, cert.ValidPrincipals, "a daemon only signs for its own target")
	ca, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caKey))
	require.NoError(t, err)
	assert.Equal(t, ca.Marshal(), cert.SignatureKey.Marshal(), "signed by the CA of the target")
}

// Unenrolling removes the daemon and spends its session with it.
func TestUnenrollDaemon(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	token := enrolled.GetAccessToken()
	control := func(procedure string) nokkuv1connect.DaemonControlServiceClient {
		return nokkuv1connect.NewDaemonControlServiceClient(srv.Client(), srv.URL,
			daemonAuth(t, cfg, key, token, procedure))
	}

	_, err := control(nokkuv1connect.DaemonControlServiceUnenrollDaemonProcedure).
		UnenrollDaemon(t.Context(), &nokkuv1.UnenrollDaemonRequest{})
	require.NoError(t, err)

	adminAuth := header("Authorization", "Bearer "+seedMember(t, cfg, workspaceID, db.RoleAdmin))
	_, err = nokkuv1connect.NewDaemonServiceClient(srv.Client(), srv.URL, adminAuth).
		GetDaemon(t.Context(), &nokkuv1.GetDaemonRequest{WorkspaceId: &workspaceID, Id: new(enrolled.GetId())})
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "the daemon is still there, got %v", err)

	_, err = control(nokkuv1connect.DaemonControlServiceSyncDaemonProcedure).
		SyncDaemon(t.Context(), &nokkuv1.SyncDaemonRequest{})
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "the session outlived the daemon, got %v", err)
}
