//go:build integration

package api_test

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

	"connectrpc.com/connect/v2"
	"github.com/coder/websocket"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokku/internal/dpop"
	nklogin "github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/core/internal/access"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/ssh"
	"github.com/nokku-sh/nokku/core/internal/sshclient/sshtest"
)

// dpopProof signs like nokkud. Only a session proof carries the token hash.
func dpopProof(t *testing.T, cfg *config.Config, key *ecdsa.PrivateKey, procedure, token string) string {
	t.Helper()
	return dpopProofWithNonce(t, key, procedure, token, cfg.IAM.DPoP.CurrentNonce())
}

func dpopProofWithNonce(
	t *testing.T,
	key *ecdsa.PrivateKey,
	procedure, token, nonce string,
) string {
	t.Helper()
	claims := map[string]any{
		"htm":   http.MethodPost,
		"htu":   testWorkspace.BaseURL + procedure,
		"iat":   time.Now().Unix(),
		"jti":   rand.Text(),
		"nonce": nonce,
	}
	if token != "" {
		claims["ath"] = dpop.ATH(token)
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
	workspaceID := testWorkspace.ID
	adminAuth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)

	created, err := nokkuv1connect.NewJoinTokenServiceClient(clientOn(srv, adminAuth)).
		CreateJoinToken(t.Context(), &nokkuv1.CreateJoinTokenRequest{
			MaxUses:     new(int32(1)),
			AutoApprove: new(true),
		})
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	enroll := func(token string, key *ecdsa.PrivateKey) (*nokkuv1.EnrollDaemonResponse, error) {
		client := nokkuv1connect.NewDaemonControlServiceClient(
			clientOn(
				srv,
				header("DPoP", dpopProof(t, cfg, key, nokkuv1connect.DaemonControlServiceEnrollDaemonProcedure, "")),
			),
		)
		return client.EnrollDaemon(t.Context(), &nokkuv1.EnrollDaemonRequest{Token: &token})
	}

	res, err := enroll(created.GetSecret(), key)
	require.NoError(t, err)
	assert.NotEmpty(t, res.GetTargetId(), "enrollment creates the target")
	assert.NotEmpty(t, res.GetAccessToken())
	assert.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED, res.GetStatus(), "auto approve token")

	daemons := nokkuv1connect.NewDaemonServiceClient(
		clientOn(srv, adminAuth),
	)
	got, err := daemons.GetDaemon(
		t.Context(),
		&nokkuv1.GetDaemonRequest{Id: new(res.GetId())},
	)
	require.NoError(t, err)
	assert.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED, got.GetDaemon().GetStatus())

	// With no workspace defaults, daemon and API agree on the built-in ones.
	assert.True(t, proto.Equal(db.DefaultDaemonConfig(), res.GetConfig()),
		"enroll answers with a complete config, got %v", res.GetConfig())
	assert.True(t, proto.Equal(db.DefaultDaemonConfig(), got.GetDaemon().GetConfig()),
		"the API reads the same config back, got %v", got.GetDaemon().GetConfig())

	_, err = daemons.UpdateDaemon(t.Context(), masked(&nokkuv1.UpdateDaemonRequest{
		Id:     new(res.GetId()),
		Config: &nokkuv1.DaemonConfig{RecordSessions: new(false)},
	}))
	require.NoError(t, err)
	got, err = daemons.GetDaemon(
		t.Context(),
		&nokkuv1.GetDaemonRequest{Id: new(res.GetId())},
	)
	require.NoError(t, err)
	want := db.DefaultDaemonConfig()
	want.RecordSessions = new(false)
	assert.True(t, proto.Equal(want, got.GetDaemon().GetConfig()),
		"an explicit off survives, unset fields read as the defaults, got %v", got.GetDaemon().GetConfig())
	assert.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED, got.GetDaemon().GetStatus(),
		"a config change leaves the status alone")

	_, err = daemons.UpdateDaemon(t.Context(), masked(&nokkuv1.UpdateDaemonRequest{
		Id:     new(res.GetId()),
		Status: nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED.Enum(),
	}))
	require.NoError(t, err)
	got, err = daemons.GetDaemon(t.Context(), &nokkuv1.GetDaemonRequest{Id: new(res.GetId())})
	require.NoError(t, err)
	assert.True(t, proto.Equal(want, got.GetDaemon().GetConfig()),
		"a status change leaves the config alone, got %v", got.GetDaemon().GetConfig())

	// The call is public, so the handler writes the audit row itself.
	require.Eventually(t, func() bool {
		rows, _ := cfg.Conn.Tenant().ListAuditLogs(wsCtx(t), &db.ListAuditLogsParams{
			Target: new(res.GetId()), Actions: []string{"EnrollDaemon"}, Limit: 1,
		})
		return len(rows) == 1
	}, 5*time.Second, 20*time.Millisecond, "no audit row for the enrollment")

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
	workspaceID := testWorkspace.ID
	adminAuth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)

	created, err := nokkuv1connect.NewJoinTokenServiceClient(clientOn(srv, adminAuth)).
		CreateJoinToken(t.Context(), &nokkuv1.CreateJoinTokenRequest{
			AutoApprove: new(true),
		})
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	enrollAuth := header("DPoP", dpopProof(t, cfg, key, nokkuv1connect.DaemonControlServiceEnrollDaemonProcedure, ""))
	enrolled, err := nokkuv1connect.NewDaemonControlServiceClient(clientOn(srv, enrollAuth)).
		EnrollDaemon(t.Context(), &nokkuv1.EnrollDaemonRequest{Token: new(created.GetSecret())})
	require.NoError(t, err)

	req := &nokkuv1.CreateSessionRequest{
		DaemonId: new(enrolled.GetId()),
		Username: new("root"),
	}
	memberToken := seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	member := nokkuv1connect.NewDaemonServiceClient(
		clientOn(srv, header("Authorization", "Bearer "+memberToken)),
	)
	accounts := nokkuv1connect.NewServiceAccountServiceClient(
		clientOn(srv, adminAuth),
	)
	sa, err := accounts.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
		Name: new(uniq("ci")),
		Role: new(nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR),
	})
	require.NoError(t, err)
	machine := nokkuv1connect.NewDaemonServiceClient(
		clientOn(
			srv,
			header("Authorization", "Bearer "+serviceAccountToken(t, accounts, sa.GetServiceAccount().GetId(), nil)),
		),
	)
	_, err = machine.CreateSession(t.Context(), req)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "service account, got %v", err)

	memberPrincipal, _, err := cfg.IAM.AuthenticateToken(wsCtx(t), memberToken, accessTokens...)
	require.NoError(t, err)

	// Membership opens nothing. A shell and a relay need a grant, as sshd does.
	openRelay := func() error {
		relayCtx, info := connect.NewClientContext(t.Context())
		info.RequestHeader().Set("Authorization", "Bearer "+memberToken)
		relay, err := nokkuv1connect.NewDaemonServiceClient(clientOn(srv)).
			Relay(relayCtx)
		if err != nil {
			return err
		}
		if err := relay.Send(&nokkuv1.RelayRequest{Msg: &nokkuv1.RelayRequest_Start{
			Start: &nokkuv1.RelayStart{DaemonId: new(enrolled.GetId())},
		}}); err != nil {
			return err
		}
		_, err = relay.Receive()
		return err
	}
	_, err = member.CreateSession(t.Context(), req)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "web session without a grant, got %v", err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(openRelay()), "relay without a grant")

	inWorkspace(t, cfg, workspaceID, func(q *db.Queries) error {
		p, err := q.CreateTargetAccount(t.Context(), &db.CreateTargetAccountParams{
			TargetID: enrolled.GetTargetId(), Username: "root",
		})
		if err != nil {
			return err
		}
		return q.PutGrant(t.Context(), &db.PutGrantParams{
			AccountID: p.ID, SubjectKind: "user", SubjectID: memberPrincipal.ID,
		})
	})
	// With the grant the relay gets past the check, the daemon is just offline.
	assert.Equal(t, connect.CodeUnavailable, connect.CodeOf(openRelay()), "relay with a grant")
	_, err = member.CreateSession(t.Context(), &nokkuv1.CreateSessionRequest{
		DaemonId: new(enrolled.GetId()),
		Username: new("postgres"),
	})
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "another account on the host, got %v", err)

	// The workspace CA signs sshtest's host cert and admits the member's.
	var user, host gossh.Signer
	inWorkspace(t, cfg, workspaceID, func(q *db.Queries) error {
		row, err := q.GetWorkspaceCA(t.Context())
		if err != nil {
			return err
		}
		if user, err = ssh.CASigner(t.Context(), q, cfg.Keyset, row.ID, gossh.UserCert); err != nil {
			return err
		}
		host, err = ssh.CASigner(t.Context(), q, cfg.Keyset, row.ID, gossh.HostCert)
		return err
	})
	sshd := sshtest.NewServerSignedBy(t, enrolled.GetTargetId(), memberPrincipal.ID, user, host)

	openShell := func() (string, *websocket.Conn) {
		res, err := member.CreateSession(t.Context(), req)
		require.NoError(t, err)
		assert.Equal(t, memberPrincipal.ID, res.GetSession().GetUserId())
		ws, _, err := websocket.Dial(
			t.Context(),
			srv.URL+"/terminal/ws?session_id="+res.GetSession().GetSessionId(),
			&websocket.DialOptions{
				HTTPClient: srv.Client(),
				HTTPHeader: http.Header{"Cookie": {sessionCookie + "=" + memberToken}},
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
	stream, err := nokkuv1connect.NewDaemonControlServiceClient(clientOn(srv)).
		Connect(controlCtx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&nokkuv1.ConnectRequest{
		Msg: &nokkuv1.ConnectRequest_Heartbeat{Heartbeat: &nokkuv1.Heartbeat{}},
	}))
	// Signed here, no require on the daemon goroutine. A proof works once.
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
			relay, err := nokkuv1connect.NewDaemonControlServiceClient(clientOn(srv)).
				DaemonRelay(relayCtx)
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
	require.Eventually(t, func() bool { return cfg.Pool.IsConnected(enrolled.GetId()) },
		5*time.Second, 20*time.Millisecond, "the control stream never registered")
	sessionID, ws := openShell()
	// The test sshd echoes stdin, a failed dial closes the socket instead.
	_ = ws.Write(t.Context(), websocket.MessageBinary, []byte("ping\n"))
	pingCtx, stopPing := context.WithTimeout(t.Context(), 3*time.Second)
	defer stopPing()
	_, _, err = ws.Read(pingCtx)
	require.NoError(t, err, "shell output never arrived")
	assert.Equal(t, "root", sshd.ConnUser(), "sshd saw the requested OS user")
	assert.Equal(t, "nokku:web:session:"+sessionID, sshd.KeyID(), "the session id travels in the certificate")
	assert.Len(t, cfg.Pool.ListSessions(enrolled.GetId()), 1)
	assert.Contains(
		t,
		certificateKeyIDs(t, cfg),
		"nokku:web:session:"+sessionID,
		"a terminal certificate needs its row",
	)

	_, res, err := websocket.Dial(t.Context(), srv.URL+"/terminal/ws?session_id="+sessionID,
		&websocket.DialOptions{
			HTTPClient: srv.Client(),
			HTTPHeader: http.Header{"Cookie": {sessionCookie + "=" + memberToken}},
		})
	require.Error(t, err, "a ticket opens one socket")
	assert.Equal(t, http.StatusNotFound, res.StatusCode)

	// The shell belongs to the socket, closing it is the whole cleanup.
	require.NoError(t, ws.CloseNow())
	assert.Eventually(t, func() bool {
		return len(cfg.Pool.ListSessions(enrolled.GetId())) == 0
	}, 5*time.Second, 20*time.Millisecond, "session outlived its socket")

	// No row, no certificate, so the shell never opens.
	restore := blockAuditWrites(t)
	_, ws = openShell()
	_, _, err = ws.Read(t.Context())
	assert.Equal(t, websocket.StatusInternalError, websocket.CloseStatus(err), "a shell opened with no row, %v", err)
	assert.Empty(t, cfg.Pool.ListSessions(enrolled.GetId()), "a session started with no row in the log")
	restore()

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
func daemonAuth(
	t *testing.T,
	cfg *config.Config,
	key *ecdsa.PrivateKey,
	token, procedure string,
) connect.ClientInterceptor {
	t.Helper()
	auth := header("Authorization", "DPoP "+token)
	proof := header("DPoP", dpopProof(t, cfg, key, procedure, token))
	return func(next connect.ClientFunc) connect.ClientFunc { return auth(proof(next)) }
}

func enrollTestDaemon(
	t *testing.T,
	cfg *config.Config,
	srv *httptest.Server,
	workspaceID string,
	autoApprove bool,
) (*ecdsa.PrivateKey, *nokkuv1.EnrollDaemonResponse) {
	t.Helper()
	adminAuth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	created, err := nokkuv1connect.NewJoinTokenServiceClient(clientOn(srv, adminAuth)).
		CreateJoinToken(t.Context(), &nokkuv1.CreateJoinTokenRequest{
			AutoApprove: &autoApprove,
		})
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	enrollAuth := header("DPoP", dpopProof(t, cfg, key, nokkuv1connect.DaemonControlServiceEnrollDaemonProcedure, ""))
	enrolled, err := nokkuv1connect.NewDaemonControlServiceClient(clientOn(srv, enrollAuth)).
		EnrollDaemon(t.Context(), &nokkuv1.EnrollDaemonRequest{Token: new(created.GetSecret())})
	require.NoError(t, err)
	return key, enrolled
}

// A daemon nobody approved may ask for its status and nothing else.
func TestPendingDaemonIsDenied(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, false)
	require.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING, enrolled.GetStatus())
	token := enrolled.GetAccessToken()

	synced, err := nokkuv1connect.NewDaemonControlServiceClient(clientOn(srv, daemonAuth(t, cfg, key, token, nokkuv1connect.DaemonControlServiceSyncDaemonProcedure))).
		SyncDaemon(t.Context(), &nokkuv1.SyncDaemonRequest{})
	require.NoError(t, err)
	assert.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING, synced.GetStatus())
	assert.Empty(t, synced.GetPrincipals())

	_, err = nokkuv1connect.NewDaemonControlServiceClient(clientOn(srv, daemonAuth(t, cfg, key, token, nokkuv1connect.DaemonControlServiceSignHostCertificateProcedure))).
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
	workspaceID := testWorkspace.ID
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	token := enrolled.GetAccessToken()

	adminAuth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	_, err := nokkuv1connect.NewDaemonServiceClient(clientOn(srv, adminAuth)).
		DeleteDaemon(t.Context(), &nokkuv1.DeleteDaemonRequest{Id: new(enrolled.GetId())})
	require.NoError(t, err)

	sync := func() (*nokkuv1.SyncDaemonResponse, error) {
		return nokkuv1connect.NewDaemonControlServiceClient(clientOn(srv, daemonAuth(t, cfg, key, token, nokkuv1connect.DaemonControlServiceSyncDaemonProcedure))).
			SyncDaemon(t.Context(), &nokkuv1.SyncDaemonRequest{})
	}
	synced, err := sync()
	require.NoError(t, err)
	assert.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_REJECTED, synced.GetStatus())

	// That answer can get lost, a host that misses it keeps serving its cache.
	synced, err = sync()
	require.NoError(t, err)
	assert.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_REJECTED, synced.GetStatus(), "the answer was only there once")

	_, err = nokkuv1connect.NewDaemonControlServiceClient(clientOn(srv,
		daemonAuth(t, cfg, key, token, nokkuv1connect.DaemonControlServiceSignHostCertificateProcedure))).
		SignHostCertificate(t.Context(), &nokkuv1.SignHostCertificateRequest{})
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "the token did more than hear REJECTED: %v", err)
}

// A failing sync only shows in the host's log, so the heartbeat must tell.
func TestDaemonThatFallsBehindShows(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	// A fresh hosted workspace is still at version 0, where nothing is behind.
	member := seedUser(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER)
	inWorkspace(t, cfg, workspaceID, func(q *db.Queries) error {
		team, err := q.CreateTeam(t.Context(), &db.CreateTeamParams{Name: uniq("behind")})
		if err != nil {
			return err
		}
		return q.AddTeamMember(t.Context(), &db.AddTeamMemberParams{TeamID: team.ID, UserID: member.ID})
	})
	token := enrolled.GetAccessToken()
	ctx, call := connect.NewClientContext(t.Context())
	call.RequestHeader().Set("Authorization", "DPoP "+token)
	call.RequestHeader().Set("DPoP", dpopProof(t, cfg, key, nokkuv1connect.DaemonControlServiceConnectProcedure, token))
	stream, err := nokkuv1connect.NewDaemonControlServiceClient(
		clientOn(srv),
	).Connect(ctx)
	require.NoError(t, err)
	go func() {
		for {
			if _, err := stream.Receive(); err != nil {
				return
			}
		}
	}()
	heartbeat := func(applied int64) {
		t.Helper()
		require.NoError(t, stream.Send(&nokkuv1.ConnectRequest{
			Msg: &nokkuv1.ConnectRequest_Heartbeat{Heartbeat: &nokkuv1.Heartbeat{StateVersion: &applied}},
		}))
	}
	behind := func() bool {
		return !cfg.Pool.BehindSince(enrolled.GetId()).IsZero()
	}

	// The first one sets what the daemon must reach by the next.
	heartbeat(0)
	require.Eventually(
		t,
		func() bool { return cfg.Pool.IsConnected(enrolled.GetId()) },
		time.Second,
		5*time.Millisecond,
	)
	heartbeat(0)
	require.Eventually(t, behind, 2*time.Second, 5*time.Millisecond, "a daemon stuck on an old version did not show")

	daemons := nokkuv1connect.NewDaemonServiceClient(clientOn(
		srv,
		header("Authorization", "Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER)),
	))
	got, err := daemons.GetDaemon(t.Context(), &nokkuv1.GetDaemonRequest{Id: new(enrolled.GetId())})
	require.NoError(t, err)
	assert.NotNil(t, got.GetDaemon().GetBehindSince(), "the console can't see it")

	var events []*db.ListAuditLogsRow
	inWorkspace(t, cfg, workspaceID, func(q *db.Queries) (err error) {
		events, err = q.ListAuditLogs(t.Context(), &db.ListAuditLogsParams{
			Actions: []string{"DaemonBehind"}, Target: new(enrolled.GetId()), Limit: 10,
		})
		return err
	})
	assert.Len(t, events, 1, "falling behind is audited once")

	var current int64
	inWorkspace(t, cfg, workspaceID, func(q *db.Queries) (err error) {
		current, err = q.GetWorkspaceStateVersion(t.Context(), workspaceID)
		return err
	})
	heartbeat(current)
	require.Eventually(
		t,
		func() bool { return !behind() },
		2*time.Second,
		5*time.Millisecond,
		"catching up did not clear it",
	)
}

// holdControlStream is a daemon's stream. An unread update covers the next.
func holdControlStream(
	t *testing.T,
	cfg *config.Config,
	srv *httptest.Server,
	key *ecdsa.PrivateKey,
	token string,
) <-chan struct{} {
	t.Helper()
	ctx, call := connect.NewClientContext(t.Context())
	call.RequestHeader().Set("Authorization", "DPoP "+token)
	call.RequestHeader().Set("DPoP",
		dpopProof(t, cfg, key, nokkuv1connect.DaemonControlServiceConnectProcedure, token))
	stream, err := nokkuv1connect.NewDaemonControlServiceClient(clientOn(srv)).
		Connect(ctx)
	require.NoError(t, err)
	updates := make(chan struct{}, 1)
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				return
			}
			if msg.GetStateUpdate() == nil {
				continue
			}
			select {
			case updates <- struct{}{}:
			default:
			}
		}
	}()
	// A heartbeat with no version earns an update, so the core has the stream.
	require.NoError(t, stream.Send(&nokkuv1.ConnectRequest{
		Msg: &nokkuv1.ConnectRequest_Heartbeat{Heartbeat: &nokkuv1.Heartbeat{}},
	}))
	require.True(t, woken(t, updates), "the core never answered the first heartbeat")
	return updates
}

func woken(t *testing.T, updates <-chan struct{}) bool {
	t.Helper()
	return assert.Eventually(t, func() bool {
		select {
		case <-updates:
			return true
		default:
			return false
		}
	}, 5*time.Second, 10*time.Millisecond, "no StateUpdate reached the daemon")
}

// One transaction revokes on every server and bumps the version once. That one
// notification must reach every daemon, not only the owner of the first deleted
// grant.
func TestRevokeAllAccessReachesEveryServer(t *testing.T) {
	n := newNKSync(t)
	cfg, srv := n.cfg, n.srv
	workspaceID := testWorkspace.ID
	revoked := seedUser(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	kept := seedUser(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)

	type server struct {
		key      *ecdsa.PrivateKey
		enrolled *nokkuv1.EnrollDaemonResponse
		updates  <-chan struct{}
	}
	servers := make([]*server, 3)
	for i := range servers {
		key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
		account, err := n.accounts.AddTargetAccount(t.Context(), &nokkuv1.AddTargetAccountRequest{
			TargetId: new(enrolled.GetTargetId()),
			Username: new("root"),
		})
		require.NoError(t, err)
		n.grant(t, account.GetAccount().GetId(), revoked.ID)
		n.grant(t, account.GetAccount().GetId(), kept.ID)
		servers[i] = &server{key: key, enrolled: enrolled}
	}
	sync := func(s *server) *nokkuv1.SyncDaemonResponse {
		res, err := nokkuv1connect.NewDaemonControlServiceClient(clientOn(srv, daemonAuth(t, cfg, s.key, s.enrolled.GetAccessToken(), nokkuv1connect.DaemonControlServiceSyncDaemonProcedure))).
			SyncDaemon(t.Context(), &nokkuv1.SyncDaemonRequest{})
		require.NoError(t, err)
		return res
	}
	principal := func(s *server, u *db.User) string {
		return nklogin.Principal(u.ID, s.enrolled.GetTargetId(), "root")
	}
	version := func() int64 {
		v, err := cfg.Conn.Sys().GetWorkspaceStateVersion(t.Context(), workspaceID)
		require.NoError(t, err)
		return v
	}

	// Expire now, or a grant another test left bumps the version later.
	require.NoError(t, access.Expire(t.Context(), cfg.Conn, cfg.Audit.Append))
	before := version()
	for _, s := range servers {
		synced := sync(s)
		require.Equal(t, before, synced.GetStateVersion(), "the daemon must start out up to date")
		require.Len(t, synced.GetPrincipals(), 1)
		require.ElementsMatch(t, []string{principal(s, revoked), principal(s, kept)},
			synced.GetPrincipals()[0].GetCertPrincipals(), "both people must be on the server before the revoke")
		s.updates = holdControlStream(t, cfg, srv, s.key, s.enrolled.GetAccessToken())
	}

	_, err := n.accounts.RevokeAllAccess(t.Context(), &nokkuv1.RevokeAllAccessRequest{
		SubjectId: &revoked.ID,
		Kind:      nokkuv1.SubjectKind_SUBJECT_KIND_USER.Enum(),
	})
	require.NoError(t, err)
	after := version()
	assert.Equal(t, before+1, after, "one transaction bumps once, however many servers its grants were on")

	for i, s := range servers {
		assert.True(t, woken(t, s.updates), "daemon %d was not told about the revoke", i)
		synced := sync(s)
		assert.Equal(t, after, synced.GetStateVersion(), "daemon %d must see the one bump", i)
		require.Len(t, synced.GetPrincipals(), 1, "daemon %d lost the account of the person who stays", i)
		assert.Equal(t, []string{principal(s, kept)}, synced.GetPrincipals()[0].GetCertPrincipals(),
			"daemon %d must drop the revoked person and keep the other one", i)
	}
}

// A host's report is a hint. What does not parse is dropped, the sync goes on.
func TestSyncDaemonReport(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	ca := workspaceCA(t, cfg)
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	token := enrolled.GetAccessToken()

	synced, err := nokkuv1connect.NewDaemonControlServiceClient(clientOn(srv, daemonAuth(t, cfg, key, token, nokkuv1connect.DaemonControlServiceSyncDaemonProcedure))).
		SyncDaemon(t.Context(), &nokkuv1.SyncDaemonRequest{
			Users:      []string{"root", "deploy", "bad name", `corp\john`},
			PrivateIps: []string{"10.0.0.5:4022", "example.com:22", "nonsense"},
		})
	require.NoError(t, err)
	assert.Equal(t, ca.GetPublicKey(), synced.GetCaPublicKey(), "the daemon trusts the CA of its target")
	assert.Equal(
		t,
		ca.GetHostPublicKey(),
		synced.GetHostCaPublicKey(),
		"and renews its host certificate from its host key",
	)
	assert.True(t, proto.Equal(db.DefaultDaemonConfig(), synced.GetConfig()),
		"the daemon is told every setting, got %v", synced.GetConfig())

	var usernames, endpoints []string
	require.NoError(t, cfg.Conn.SysTx(t.Context(), func(q *db.Queries) error {
		target, err := q.GetTargetByDaemon(t.Context(), new(enrolled.GetId()))
		if err != nil {
			return err
		}
		endpoints = target.Endpoints
		rows, err := q.GetTargetAccountsByTargetIDs(t.Context(), []string{target.ID})
		for _, r := range rows {
			usernames = append(usernames, r.TargetAccount.Username)
			assert.NotNil(t, r.TargetAccount.SeenAt, "%s was reported by the host", r.TargetAccount.Username)
		}
		return err
	}))
	assert.Equal(t, []string{"deploy", "root"}, usernames)
	assert.Equal(t, []string{"10.0.0.5:4022"}, endpoints)
}

func TestSignHostCertificate(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	caKey := workspaceCA(t, cfg).GetHostPublicKey()
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)

	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	hostPub, err := gossh.NewPublicKey(&hostKey.PublicKey)
	require.NoError(t, err)

	sign := func() (*nokkuv1.SignHostCertificateResponse, error) {
		return nokkuv1connect.NewDaemonControlServiceClient(clientOn(srv, daemonAuth(
			t, cfg, key, enrolled.GetAccessToken(),
			nokkuv1connect.DaemonControlServiceSignHostCertificateProcedure,
		))).
			SignHostCertificate(t.Context(), &nokkuv1.SignHostCertificateRequest{
				PublicKey: new(string(gossh.MarshalAuthorizedKey(hostPub))),
			})
	}
	res, err := sign()
	require.NoError(t, err)

	parsed, _, _, _, err := gossh.ParseAuthorizedKey([]byte(res.GetSignedCertificate()))
	require.NoError(t, err)
	cert, ok := parsed.(*gossh.Certificate)
	require.True(t, ok, "not a certificate")
	assert.Equal(t, uint32(gossh.HostCert), cert.CertType)
	assert.Equal(t, []string{enrolled.GetTargetId()}, cert.ValidPrincipals, "a daemon only signs for its own target")
	ca, _, _, _, err := gossh.ParseAuthorizedKey([]byte(caKey))
	require.NoError(t, err)
	assert.Equal(t, ca.Marshal(), cert.SignatureKey.Marshal(), "signed by the host key of the target's CA")

	blockAuditWrites(t)
	_, err = sign()
	require.Error(t, err, "a host certificate went out with no row in the log")
}

// Unenrolling removes the daemon and spends its session with it.
func TestUnenrollDaemon(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	key, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	token := enrolled.GetAccessToken()
	control := func(procedure string) nokkuv1connect.DaemonControlServiceClient {
		return nokkuv1connect.NewDaemonControlServiceClient(
			clientOn(srv, daemonAuth(t, cfg, key, token, procedure)),
		)
	}

	_, err := control(nokkuv1connect.DaemonControlServiceUnenrollDaemonProcedure).
		UnenrollDaemon(t.Context(), &nokkuv1.UnenrollDaemonRequest{})
	require.NoError(t, err)

	adminAuth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	_, err = nokkuv1connect.NewDaemonServiceClient(clientOn(srv, adminAuth)).
		GetDaemon(t.Context(), &nokkuv1.GetDaemonRequest{Id: new(enrolled.GetId())})
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "the daemon is still there, got %v", err)

	_, err = control(nokkuv1connect.DaemonControlServiceSyncDaemonProcedure).
		SyncDaemon(t.Context(), &nokkuv1.SyncDaemonRequest{})
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err), "the session outlived the daemon, got %v", err)
}

// blockAuditWrites takes the app's insert on the log until the test or restore.
func blockAuditWrites(t *testing.T) (restore func()) {
	t.Helper()
	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	restore = func() {
		_, err := owner.Exec(context.WithoutCancel(t.Context()), "GRANT INSERT ON audit.audit_logs TO nokku_app")
		require.NoError(t, err)
	}
	t.Cleanup(func() { restore(); _ = owner.Close(context.WithoutCancel(t.Context())) })
	_, err = owner.Exec(t.Context(), "REVOKE INSERT ON audit.audit_logs FROM nokku_app")
	require.NoError(t, err)
	return restore
}

// certificateKeyIDs reads the key id of every certificate the log holds.
func certificateKeyIDs(t *testing.T, cfg *config.Config) []string {
	t.Helper()
	var rows []*db.ListAuditLogsRow
	require.NoError(t, cfg.Conn.TenantTx(wsCtx(t), func(q *db.Queries) (err error) {
		rows, err = q.ListAuditLogs(t.Context(), &db.ListAuditLogsParams{
			Actions: []string{"SignSSHCertificate"}, Limit: 1000,
		})
		return err
	}))
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		var details struct {
			KeyID string `json:"key_id"`
		}
		require.NoError(t, json.Unmarshal(row.Details, &details))
		ids = append(ids, details.KeyID)
	}
	return ids
}

// A person sees whether a server records them before they log in, and nothing else of its daemon's rules.
func TestAccessTellsRecording(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	_, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	person := seedUser(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	inWorkspace(t, cfg, workspaceID, func(q *db.Queries) error {
		p, err := q.CreateTargetAccount(t.Context(), &db.CreateTargetAccountParams{
			TargetID: enrolled.GetTargetId(), Username: "root",
		})
		if err != nil {
			return err
		}
		return q.PutGrant(t.Context(), &db.PutGrantParams{
			AccountID: p.ID, SubjectKind: db.SubjectKindUser, SubjectID: person.ID,
		})
	})
	editor := nokkuv1connect.NewDaemonServiceClient(clientOn(srv, header("Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR))))
	self := nokkuv1connect.NewTargetServiceClient(clientOn(srv, header("Authorization",
		"Bearer "+sessionFor(t, cfg, person))))

	records := func(on bool) *nokkuv1.DaemonConfig {
		_, err := editor.UpdateDaemon(t.Context(), masked(&nokkuv1.UpdateDaemonRequest{
			Id:     new(enrolled.GetId()),
			Config: &nokkuv1.DaemonConfig{RecordSessions: new(on), AllowForwarding: new(true)},
		}))
		require.NoError(t, err)
		res, err := self.GetSubjectAccess(t.Context(), &nokkuv1.GetSubjectAccessRequest{SubjectId: &person.ID})
		require.NoError(t, err)
		require.Len(t, res.GetDaemons(), 1)
		return res.GetDaemons()[0].GetConfig()
	}

	assert.True(t, records(true).GetRecordSessions())
	assert.False(t, records(false).GetRecordSessions())
	assert.Nil(t, records(false).AllowForwarding, "a member learns only whether it records")
}

// A server carries its daemon, so the server list needs no second call. A server set up with nk sync has none.
func TestServersCarryTheirDaemon(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	_, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, false)
	manual := seedTarget(t, cfg, workspaceID)
	targets := nokkuv1connect.NewTargetServiceClient(clientOn(srv, header("Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER))))

	list, err := targets.ListTargets(t.Context(), &nokkuv1.ListTargetsRequest{
		Limit: new(int32(10)), DaemonId: new(enrolled.GetId()),
	})
	require.NoError(t, err)
	require.Len(t, list.GetTargets(), 1)
	d := list.GetTargets()[0].GetDaemon()
	assert.Equal(t, enrolled.GetId(), d.GetId())
	assert.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING, d.GetStatus(), "the list shows it waits for approval")
	assert.False(t, d.GetOnline())

	got, err := targets.GetTarget(t.Context(), &nokkuv1.GetTargetRequest{Id: new(enrolled.GetTargetId())})
	require.NoError(t, err)
	assert.Equal(t, enrolled.GetId(), got.GetTarget().GetDaemon().GetId())

	got, err = targets.GetTarget(t.Context(), &nokkuv1.GetTargetRequest{Id: &manual})
	require.NoError(t, err)
	assert.Nil(t, got.GetTarget().GetDaemon(), "an nk sync server has no daemon")

	ids := func(status nokkuv1.TargetStatus) []string {
		res, err := targets.ListTargets(t.Context(), &nokkuv1.ListTargetsRequest{
			Limit: new(int32(100)), Status: status.Enum(),
		})
		require.NoError(t, err)
		var out []string
		for _, t := range res.GetTargets() {
			out = append(out, t.GetId())
		}
		return out
	}
	assert.Contains(t, ids(nokkuv1.TargetStatus_TARGET_STATUS_PENDING), enrolled.GetTargetId())
	assert.NotContains(t, ids(nokkuv1.TargetStatus_TARGET_STATUS_PENDING), manual)
	assert.Contains(t, ids(nokkuv1.TargetStatus_TARGET_STATUS_MANUAL), manual)
	assert.NotContains(t, ids(nokkuv1.TargetStatus_TARGET_STATUS_MANUAL), enrolled.GetTargetId())
	assert.NotContains(t, ids(nokkuv1.TargetStatus_TARGET_STATUS_OFFLINE), enrolled.GetTargetId(),
		"a daemon nobody approved is pending, not offline")
	assert.NotContains(t, ids(nokkuv1.TargetStatus_TARGET_STATUS_ONLINE), enrolled.GetTargetId())

	picked, err := targets.ListTargets(t.Context(), &nokkuv1.ListTargetsRequest{
		Limit: new(int32(100)), Ids: []string{manual},
	})
	require.NoError(t, err)
	require.Len(t, picked.GetTargets(), 1, "the ids filter keeps only the picked servers")
	assert.Equal(t, manual, picked.GetTargets()[0].GetId())
}
