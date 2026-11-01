//go:build integration

package api_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
	nklogin "github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// No grant, no certificate. The daemon gets the very principal it carries.
func TestSignSSHCertificate(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	adminAuth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	daemonKey, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, false)
	targetID := enrolled.GetTargetId()
	otherID := seedTarget(t, cfg, workspaceID)

	memberToken := seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	member, _, err := cfg.IAM.AuthenticateToken(wsCtx(t), memberToken, accessTokens...)
	require.NoError(t, err)
	wantPrincipal := member.ID + "@" + targetID + ":root"
	nkToken := cliSessionFor(t, cfg, &db.User{ID: member.ID, Active: true})

	targetAccounts := nokkuv1connect.NewTargetAccountServiceClient(
		clientOn(srv, adminAuth),
	)
	root, err := targetAccounts.AddTargetAccount(t.Context(), &nokkuv1.AddTargetAccountRequest{
		TargetId: &targetID,
		Username: new("root"),
	})
	require.NoError(t, err)
	grant := &nokkuv1.AddSubjectsRequest{
		Id:         new(root.GetAccount().GetId()),
		Kind:       nokkuv1.SubjectKind_SUBJECT_KIND_USER.Enum(),
		SubjectIds: []string{member.ID},
	}
	_, err = targetAccounts.AddSubjects(t.Context(), grant)
	require.NoError(t, err)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := gossh.NewPublicKey(pub)
	require.NoError(t, err)
	sign := func(target string) ([]string, error) {
		res, err := nokkuv1connect.NewCertificateServiceClient(clientOn(srv, header("Authorization", "Bearer "+nkToken))).
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

	_, err = sign(uuid.NewV7().String())
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err),
		"an unknown id must answer like a missing grant, %v", err)

	_, err = sign(targetID)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err),
		"a daemon nobody approved got a certificate signed, %v", err)
	_, err = nokkuv1connect.NewDaemonServiceClient(clientOn(srv, adminAuth)).
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

	synced, err := nokkuv1connect.NewDaemonControlServiceClient(clientOn(srv, daemonAuth(t, cfg, daemonKey, enrolled.GetAccessToken(),
		nokkuv1connect.DaemonControlServiceSyncDaemonProcedure))).
		SyncDaemon(t.Context(), &nokkuv1.SyncDaemonRequest{})
	require.NoError(t, err)
	require.Len(t, synced.GetPrincipals(), 1)
	assert.Equal(t, []string{wantPrincipal}, synced.GetPrincipals()[0].GetCertPrincipals(),
		"the daemon must be told the principal the certificate carries")

	_, err = targetAccounts.RemoveSubjects(t.Context(), &nokkuv1.RemoveSubjectsRequest{
		Id:         grant.Id,
		Kind:       grant.Kind,
		SubjectIds: grant.GetSubjectIds(),
	})
	require.NoError(t, err)
	_, err = sign(targetID)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err),
		"a revoked grant still got a certificate signed, %v", err)

	// A certificate goes out only once the log has it, and gets one row.
	_, err = targetAccounts.AddSubjects(t.Context(), grant)
	require.NoError(t, err)
	issued := func() int {
		var rows []*db.ListAuditLogsRow
		require.NoError(t, cfg.Conn.TenantTx(wsCtx(t), func(q *db.Queries) (err error) {
			rows, err = q.ListAuditLogs(t.Context(), &db.ListAuditLogsParams{
				Actions: []string{"SignSSHCertificate"}, Limit: 1000,
			})
			return err
		}))
		return len(rows)
	}
	before := issued()
	_, err = sign(targetID)
	require.NoError(t, err)
	assert.Equal(t, before+1, issued(), "a certificate needs exactly one row")

	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	restore := func() {
		_, err := owner.Exec(context.WithoutCancel(t.Context()), "GRANT INSERT ON audit.audit_logs TO nokku_app")
		require.NoError(t, err)
	}
	t.Cleanup(func() { restore(); _ = owner.Close(context.WithoutCancel(t.Context())) })
	_, err = owner.Exec(t.Context(), "REVOKE INSERT ON audit.audit_logs FROM nokku_app")
	require.NoError(t, err)
	_, err = sign(targetID)
	require.Error(t, err, "a certificate went out with no row in the log")
	restore()
}

// A service account's certificate lives an hour at most, never past its token.
func TestServiceAccountCertificateLifetime(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := testWorkspace.ID
	adminAuth := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
	)
	_, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	require.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED, enrolled.GetStatus())
	targetID := enrolled.GetTargetId()

	accounts := nokkuv1connect.NewServiceAccountServiceClient(
		clientOn(srv, adminAuth),
	)
	created, err := accounts.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
		Name: new(uniq("ci")),
	})
	require.NoError(t, err)
	id := created.GetServiceAccount().GetId()
	tokenExpiry := time.Now().Add(10 * time.Minute)
	short := serviceAccountToken(t, accounts, id, timestamppb.New(tokenExpiry))

	targetAccounts := nokkuv1connect.NewTargetAccountServiceClient(
		clientOn(srv, adminAuth),
	)
	root, err := targetAccounts.AddTargetAccount(t.Context(), &nokkuv1.AddTargetAccountRequest{
		TargetId: &targetID,
		Username: new("root"),
	})
	require.NoError(t, err)
	_, err = targetAccounts.AddSubjects(t.Context(), &nokkuv1.AddSubjectsRequest{
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
		res, err := nokkuv1connect.NewCertificateServiceClient(clientOn(srv, header("Authorization", "Bearer "+token))).
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
		"a token good for a month gets the hour, the cap follows the token and not the account")
}

// setCA changes the shared workspace CA for one test, cleanup puts it back.
func setCA(
	t *testing.T,
	cfg *config.Config,
	certs nokkuv1connect.CertificateServiceClient,
	change *nokkuv1.UpdateCertificateAuthorityRequest,
) {
	t.Helper()
	ca := workspaceCA(t, cfg)
	t.Cleanup(func() {
		_, err := certs.UpdateCertificateAuthority(context.WithoutCancel(t.Context()),
			masked(&nokkuv1.UpdateCertificateAuthorityRequest{
				UserDefaultTtl: ca.GetUserDefaultTtl(),
				UserMaxTtl:     ca.GetUserMaxTtl(),
				SourceAddress:  new(ca.GetSourceAddress()),
			}))
		require.NoError(t, err)
	})
	_, err := certs.UpdateCertificateAuthority(t.Context(), masked(change))
	require.NoError(t, err)
}

// A person gets the CA's source list and no forced command. A service account
// gets its own limits and nothing from the CA, an office list must not block a
// hosted runner.
func TestCertificateLimitsPerSubjectKind(t *testing.T) {
	const (
		day        = 24 * time.Hour
		officeList = "10.0.0.0/8,192.0.2.7"
	)
	n := newNKSync(t)
	workspaceID := testWorkspace.ID
	adminAuth := header("Authorization",
		"Bearer "+seedMember(t, n.cfg, workspaceID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN))
	admin := clientOn(n.srv, adminAuth)

	setCA(t, n.cfg, n.certs, &nokkuv1.UpdateCertificateAuthorityRequest{SourceAddress: new(officeList)})
	ca := workspaceCA(t, n.cfg)
	require.Equal(t, 16*time.Hour, ca.GetUserDefaultTtl().AsDuration(), "the rows below assume the built-in default")
	require.Equal(t, 7*day, ca.GetUserMaxTtl().AsDuration(), "the rows below assume the built-in max")

	personID, personToken := n.person(t)
	accounts := nokkuv1connect.NewServiceAccountServiceClient(admin)
	serviceLimits := map[string]string{
		"force-command":  "/usr/local/bin/deploy",
		"source-address": "198.51.100.0/24",
	}
	created, err := accounts.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
		Name:          new(uniq("ci")),
		ForceCommand:  new(serviceLimits["force-command"]),
		SourceAddress: new(serviceLimits["source-address"]),
	})
	require.NoError(t, err)
	serviceID := created.GetServiceAccount().GetId()
	serviceToken := serviceAccountToken(t, accounts, serviceID, nil)
	plain, err := accounts.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
		Name: new(uniq("plain-ci")),
	})
	require.NoError(t, err)
	plainID := plain.GetServiceAccount().GetId()
	plainToken := serviceAccountToken(t, accounts, plainID, nil)
	grantBoth := func(accountID string) {
		n.grant(t, accountID, personID)
		_, err := n.accounts.AddSubjects(t.Context(), &nokkuv1.AddSubjectsRequest{
			Id:         &accountID,
			Kind:       nokkuv1.SubjectKind_SUBJECT_KIND_SERVICE_ACCOUNT.Enum(),
			SubjectIds: []string{serviceID, plainID},
		})
		require.NoError(t, err)
	}

	_, enrolled := enrollTestDaemon(t, n.cfg, n.srv, workspaceID, true)
	daemonTarget := enrolled.GetTargetId()
	daemonAccount, err := n.accounts.AddTargetAccount(t.Context(), &nokkuv1.AddTargetAccountRequest{
		TargetId: &daemonTarget,
		Username: new("root"),
	})
	require.NoError(t, err)
	grantBoth(daemonAccount.GetAccount().GetId())
	syncTarget, syncAccount := n.target(t, "root")
	grantBoth(syncAccount)

	type caller struct {
		id, token string
		limits    map[string]string
	}
	person := caller{personID, personToken, map[string]string{"source-address": officeList}}
	service := caller{serviceID, serviceToken, serviceLimits}
	onDaemon := func(c caller) []string {
		return []string{nklogin.Principal(c.id, daemonTarget, "root")}
	}
	onSync := func(c caller) []string {
		return []string{nklogin.Principal(c.id, syncTarget, "root"), nklogin.ServerPrincipal(syncTarget, "root")}
	}

	type row struct {
		name       string
		caller     caller
		target     string
		asked      time.Duration
		want       time.Duration
		principals []string
	}
	check := func(t *testing.T, tt row) {
		t.Helper()
		cert, err := n.sign(t, tt.caller.token, tt.target, tt.asked)
		require.NoError(t, err)
		assert.InDelta(t, tt.want, lifetime(cert), float64(2*time.Second), "wrong lifetime")
		assert.Equal(t, tt.principals, cert.ValidPrincipals, "wrong principals")
		assert.Equal(t, tt.caller.limits, cert.CriticalOptions, "the wrong limits reached the certificate")
	}

	for _, tt := range []row{
		{"person with a daemon, nothing asked", person, daemonTarget, 0, 16 * time.Hour, onDaemon(person)},
		{"person with a daemon, under the max", person, daemonTarget, 2 * day, 2 * day, onDaemon(person)},
		{"person with a daemon, at the max", person, daemonTarget, 7 * day, 7 * day, onDaemon(person)},
		{
			"person with a daemon, over the max gets the default",
			person,
			daemonTarget,
			8 * day,
			16 * time.Hour,
			onDaemon(person),
		},
		{"person without a daemon, nothing asked", person, syncTarget, 0, time.Hour, onSync(person)},
		{"person without a daemon, under the hour", person, syncTarget, 10 * time.Minute, 10 * time.Minute, onSync(person)},
		{"person without a daemon, over the hour", person, syncTarget, 2 * day, time.Hour, onSync(person)},
		{"person without a daemon, over the max", person, syncTarget, 8 * day, time.Hour, onSync(person)},
		{"service account with a daemon, nothing asked", service, daemonTarget, 0, time.Hour, onDaemon(service)},
		{
			"service account with a daemon, under the hour",
			service,
			daemonTarget,
			10 * time.Minute,
			10 * time.Minute,
			onDaemon(service),
		},
		{"service account with a daemon, over the hour", service, daemonTarget, 2 * day, time.Hour, onDaemon(service)},
		{"service account without a daemon, over the hour", service, syncTarget, 2 * day, time.Hour, onSync(service)},
	} {
		t.Run(tt.name, func(t *testing.T) { check(t, tt) })
	}

	t.Run("a service account with no limits gets none", func(t *testing.T) {
		cert, err := n.sign(t, plainToken, daemonTarget, 0)
		require.NoError(t, err)
		assert.Empty(t, cert.CriticalOptions, "the CA's settings reached a service account")
	})

	t.Run("a CA under the hour", func(t *testing.T) {
		setCA(t, n.cfg, n.certs, &nokkuv1.UpdateCertificateAuthorityRequest{
			UserDefaultTtl: durationpb.New(20 * time.Minute),
			UserMaxTtl:     durationpb.New(30 * time.Minute),
		})
		for _, tt := range []row{
			{"person without a daemon", person, syncTarget, 0, 20 * time.Minute, onSync(person)},
			{"service account", service, syncTarget, 0, 20 * time.Minute, onSync(service)},
			{"service account, over the max", service, syncTarget, 2 * day, 20 * time.Minute, onSync(service)},
		} {
			t.Run(tt.name, func(t *testing.T) { check(t, tt) })
		}
	})

	t.Run("a CA with no source list", func(t *testing.T) {
		setCA(t, n.cfg, n.certs, &nokkuv1.UpdateCertificateAuthorityRequest{SourceAddress: new("")})
		cert, err := n.sign(t, personToken, daemonTarget, 0)
		require.NoError(t, err)
		assert.Empty(t, cert.CriticalOptions, "an empty list must add nothing")
	})
}

// The list is stored the way a server reads it, an unreadable one is refused.
func TestCASourceList(t *testing.T) {
	cfg, srv := newTestAPI(t)
	admin := nokkuv1connect.NewCertificateServiceClient(
		clientOn(srv, header(
			"Authorization",
			"Bearer "+seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN),
		)),
	)

	setCA(t, cfg, admin, &nokkuv1.UpdateCertificateAuthorityRequest{SourceAddress: new("10.0.0.0/8, 192.0.2.7")})
	assert.Equal(t, "10.0.0.0/8,192.0.2.7", workspaceCA(t, cfg).GetSourceAddress())

	_, err := admin.UpdateCertificateAuthority(t.Context(), masked(&nokkuv1.UpdateCertificateAuthorityRequest{
		SourceAddress: new("the office"),
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "got %v", err)

	// An update that doesn't name it keeps it, an empty one takes it away.
	res, err := admin.UpdateCertificateAuthority(t.Context(), masked(&nokkuv1.UpdateCertificateAuthorityRequest{
		HostTtl: durationpb.New(90 * 24 * time.Hour),
	}))
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.0/8,192.0.2.7", res.GetCertificateAuthority().GetSourceAddress())
	res, err = admin.UpdateCertificateAuthority(t.Context(), masked(&nokkuv1.UpdateCertificateAuthorityRequest{
		SourceAddress: new(""),
	}))
	require.NoError(t, err)
	assert.Empty(t, res.GetCertificateAuthority().GetSourceAddress())
}
