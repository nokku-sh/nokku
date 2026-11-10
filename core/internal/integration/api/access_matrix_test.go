//go:build integration

package api_test

import (
	"cmp"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"fmt"
	"maps"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// matrixAccounts are on every target. A web session asks for the first three.
var matrixAccounts = []string{"root", "deploy", "ops", "backup"}

var matrixUUID = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// token is a browser session, signToken nk's session or a service account key.
type matrixCaller struct {
	label, token, signToken string
}

type matrixTarget struct {
	label, id string
	// daemonID, key and token stay empty without a daemon.
	daemonID string
	key      *ecdsa.PrivateKey
	token    string
}

type matrixSubject struct {
	label, id string
}

// matrixReportRow is the part of an access report row the matrix records.
type matrixReportRow struct {
	Kind              string     `json:"kind"`
	SubjectID         string     `json:"subject_id"`
	Active            bool       `json:"active"`
	Via               string     `json:"via"`
	Target            string     `json:"target"`
	Account           string     `json:"account"`
	ExpiresAt         *time.Time `json:"expires_at"`
	LastCertificateAt *time.Time `json:"last_certificate_at"`
	Enforced          bool       `json:"enforced"`
	Stale             bool       `json:"stale"`
}

type matrixFixture struct {
	cfg       *config.Config
	srv       *httptest.Server
	admin     connect.ClientInterceptor
	publicKey string
	// labels maps each id, name and key made here to its golden file name.
	labels   map[string]string
	replacer *strings.Replacer
	callers  []matrixCaller
	targets  []matrixTarget
	subjects []matrixSubject
}

// TestAccessMatrix pins every access decision as it is, known gaps included.
func TestAccessMatrix(t *testing.T) {
	f := seedMatrix(t)

	// Signing goes first, the report at the end shows who got a certificate.
	var lines []string
	lines = append(lines, f.signLines(t)...)
	lines = append(lines, f.sessionLines(t)...)
	lines = append(lines, f.relayLines(t)...)
	lines = append(lines, f.syncLines(t)...)
	lines = append(lines, f.selfAccessLines(t)...)
	lines = append(lines, f.subjectAccessLines(t)...)
	lines = append(lines, f.reportLines(t)...)
	for i, line := range lines {
		lines[i] = f.scrub(line)
		require.NotRegexp(t, matrixUUID, lines[i], "an id has no label")
		require.NotContains(t, lines[i], "mx-", "a name has no label")
	}
	slices.Sort(lines)
	assertGolden(t, "access_matrix.golden", lines)
}

func seedMatrix(t *testing.T) *matrixFixture {
	t.Helper()
	cfg, srv := newTestAPI(t)
	f := &matrixFixture{
		cfg: cfg,
		srv: srv,
		admin: header("Authorization",
			"Bearer "+seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)),
		labels: map[string]string{},
	}

	ca := workspaceCA(t, cfg)
	f.labels[ca.GetId()] = "ca-active"
	f.labels[strings.TrimSpace(ca.GetUserPublicKey())] = "ca-active.user-key"
	f.labels[strings.TrimSpace(ca.GetHostPublicKey())] = "ca-active.host-key"
	f.seedDaemonTarget(t, "accepted", nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED)
	f.seedDaemonTarget(t, "pending", nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING)
	f.seedDaemonTarget(t, "rejected", nokkuv1.DaemonStatus_DAEMON_STATUS_REJECTED)
	f.seedDaemonlessTarget(t, "daemonless")

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := gossh.NewPublicKey(pub)
	require.NoError(t, err)
	f.publicKey = string(gossh.MarshalAuthorizedKey(sshPub))

	f.seedSubjects(t)

	pairs := make([]string, 0, 2*len(f.labels))
	for _, raw := range slices.Sorted(maps.Keys(f.labels)) {
		pairs = append(pairs, raw, f.labels[raw])
	}
	f.replacer = strings.NewReplacer(pairs...)
	return f
}

func (f *matrixFixture) seedDaemonTarget(
	t *testing.T,
	label string,
	status nokkuv1.DaemonStatus,
) {
	t.Helper()
	ws := testWorkspace.ID
	key, enrolled := enrollTestDaemon(t, f.cfg, f.srv, ws, status != nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING)
	if status == nokkuv1.DaemonStatus_DAEMON_STATUS_REJECTED {
		_, err := nokkuv1connect.NewDaemonServiceClient(f.adminClient()).UpdateDaemon(t.Context(),
			masked(&nokkuv1.UpdateDaemonRequest{Id: enrolled.Id, Status: &status}))
		require.NoError(t, err)
	}
	f.labels[enrolled.GetId()] = label + "-daemon"
	f.addTarget(t, matrixTarget{
		label:    label,
		id:       enrolled.GetTargetId(),
		daemonID: enrolled.GetId(),
		key:      key,
		token:    enrolled.GetAccessToken(),
	})
}

// seedDaemonlessTarget is a host that runs nk sync instead of a daemon.
func (f *matrixFixture) seedDaemonlessTarget(t *testing.T, label string) {
	t.Helper()
	var id string
	inWorkspace(t, f.cfg, testWorkspace.ID, func(q *db.Queries) error {
		target, err := q.CreateTarget(t.Context(), &db.CreateTargetParams{Name: uniq("mx-" + label)})
		if err != nil {
			return err
		}
		id = target.ID
		return nil
	})
	f.addTarget(t, matrixTarget{label: label, id: id})
}

func (f *matrixFixture) addTarget(t *testing.T, tg matrixTarget) {
	t.Helper()
	row, err := f.cfg.Conn.Sys().GetTarget(t.Context(), tg.id)
	require.NoError(t, err)
	f.labels[tg.id] = tg.label
	f.labels[row.Name] = tg.label
	f.targets = append(f.targets, tg)
}

// seedSubjects grants alike on every target, only the daemon differs.
//
//	root    alice for good, dave for good, carol until an hour ago
//	deploy  team staff (bob, dave), service account ci
//	ops     carol for another day
//	backup  team nobody, which has no members
//
// eve holds nothing, dave is deactivated after his session was issued.
func (f *matrixFixture) seedSubjects(t *testing.T) {
	t.Helper()
	ws := testWorkspace.ID
	now := time.Now()
	var alice, bob, carol, dave, eve, staff, nobody, ci string
	inWorkspace(t, f.cfg, ws, func(q *db.Queries) error {
		user := func(label string) string {
			u, err := q.CreateUser(t.Context(), &db.CreateUserParams{
				Email: uuid.New().String() + "@matrix.test",
				Name:  "mx-" + label,
				Role:  nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
			})
			require.NoError(t, err)
			f.labels[u.ID] = label
			return u.ID
		}
		team := func(label string, members ...string) string {
			name := uniq("mx-" + label)
			created, err := q.CreateTeam(t.Context(), &db.CreateTeamParams{Name: name})
			require.NoError(t, err)
			for _, userID := range members {
				err := q.AddTeamMember(t.Context(), &db.AddTeamMemberParams{UserID: userID, TeamID: created.ID})
				require.NoError(t, err)
			}
			f.labels[created.ID] = label
			f.labels[name] = label
			return created.ID
		}
		alice, bob, carol, dave, eve = user("alice"), user("bob"), user("carol"), user("dave"), user("eve")
		staff, nobody = team("staff", bob, dave), team("nobody")
		var err error
		ci, err = q.CreateServiceAccount(t.Context(), &db.CreateServiceAccountParams{
			Name: uniq("mx-ci"),
			Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
		})
		require.NoError(t, err)
		f.labels[ci] = "ci"

		for _, tg := range f.targets {
			accounts := map[string]string{}
			for _, username := range matrixAccounts {
				a, err := q.CreateTargetAccount(t.Context(), &db.CreateTargetAccountParams{
					TargetID: tg.id,
					Username: username,
				})
				require.NoError(t, err)
				accounts[username] = a.ID
			}
			grant := func(username, kind, subjectID string, expiresAt *time.Time) {
				require.NoError(t, q.PutGrant(t.Context(), &db.PutGrantParams{
					AccountID:   accounts[username],
					SubjectKind: kind,
					SubjectID:   subjectID,
					ExpiresAt:   expiresAt,
				}))
			}
			grant("root", db.SubjectKindUser, alice, nil)
			grant("root", db.SubjectKindUser, dave, nil)
			grant("root", db.SubjectKindUser, carol, new(now.Add(-time.Hour)))
			grant("deploy", db.SubjectKindTeam, staff, nil)
			grant("deploy", db.SubjectKindServiceAccount, ci, nil)
			grant("ops", db.SubjectKindUser, carol, new(now.Add(24*time.Hour)))
			grant("backup", db.SubjectKindTeam, nobody, nil)
		}
		return nil
	})

	for _, c := range []matrixSubject{{"alice", alice}, {"bob", bob}, {"carol", carol}, {"dave", dave}, {"eve", eve}} {
		u := &db.User{ID: c.id, Active: true}
		f.callers = append(f.callers,
			matrixCaller{c.label, sessionFor(t, f.cfg, u), cliSessionFor(t, f.cfg, u, f.publicKey)})
	}
	accounts := nokkuv1connect.NewServiceAccountServiceClient(f.adminClient())
	key := serviceAccountToken(t, accounts, ci, nil)
	f.callers = append(f.callers, matrixCaller{"ci", key, key})
	_, err := nokkuv1connect.NewWorkspaceServiceClient(f.adminClient()).SetUserActive(t.Context(),
		&nokkuv1.SetUserActiveRequest{UserId: &dave, Active: new(false)})
	require.NoError(t, err)

	f.subjects = []matrixSubject{
		{"alice", alice},
		{"bob", bob},
		{"carol", carol},
		{"dave", dave},
		{"eve", eve},
		{"staff", staff},
		{"nobody", nobody},
		{"ci", ci},
	}
}

func (f *matrixFixture) signLines(t *testing.T) []string {
	t.Helper()
	var lines []string
	for _, c := range f.callers {
		for _, tg := range f.targets {
			got := f.sign(t, c.signToken, tg.id)
			lines = append(lines, fmt.Sprintf("SignSSHCertificate %s %s: %s", c.label, tg.label, got))
		}
	}
	alice, accepted := f.callers[0], f.targets[0]
	lines = append(lines, fmt.Sprintf("SignSSHCertificate %s browser session %s: %s",
		alice.label, accepted.label, f.sign(t, alice.token, accepted.id)))
	return lines
}

func (f *matrixFixture) sign(t *testing.T, token, targetID string) string {
	t.Helper()
	res, err := nokkuv1connect.NewCertificateServiceClient(f.as(token)).SignSSHCertificate(t.Context(),
		&nokkuv1.SignSSHCertificateRequest{TargetId: &targetID, PublicKey: &f.publicKey})
	if err != nil {
		return errText(err)
	}
	key, _, _, _, err := gossh.ParseAuthorizedKey([]byte(res.GetSignedCertificate()))
	require.NoError(t, err)
	cert, ok := key.(*gossh.Certificate)
	require.True(t, ok, "the answer is not a certificate")
	return "principals " + f.list(cert.ValidPrincipals)
}

func (f *matrixFixture) sessionLines(t *testing.T) []string {
	t.Helper()
	var lines []string
	for _, c := range f.callers {
		for _, tg := range f.daemonTargets() {
			for _, username := range matrixAccounts[:3] {
				_, err := nokkuv1connect.NewDaemonServiceClient(f.as(c.token)).CreateSession(t.Context(),
					&nokkuv1.CreateSessionRequest{DaemonId: &tg.daemonID, Username: &username})
				got := "ticket"
				if err != nil {
					got = errText(err)
				}
				lines = append(lines, fmt.Sprintf("CreateSession %s %s %s: %s", c.label, tg.label, username, got))
			}
		}
	}
	return lines
}

// With no control stream, a relay past the grant check ends unavailable.
func (f *matrixFixture) relayLines(t *testing.T) []string {
	t.Helper()
	var lines []string
	for _, c := range f.callers {
		for _, tg := range f.daemonTargets() {
			lines = append(lines, fmt.Sprintf("Relay %s %s: %s", c.label, tg.label, f.relay(t, c.token, tg.daemonID)))
		}
	}
	return lines
}

func (f *matrixFixture) relay(t *testing.T, token, daemonID string) string {
	t.Helper()
	ctx, info := connect.NewClientContext(t.Context())
	info.RequestHeader().Set("Authorization", "Bearer "+token)
	stream, err := nokkuv1connect.NewDaemonServiceClient(f.conn()).Relay(ctx)
	if err != nil {
		return errText(err)
	}
	defer func() { _ = stream.Close() }()
	// A refused stream fails send or receive, and receive has the error.
	_ = stream.Send(&nokkuv1.RelayRequest{Msg: &nokkuv1.RelayRequest_Start{
		Start: &nokkuv1.RelayStart{DaemonId: &daemonID},
	}})
	if _, err := stream.Receive(); err != nil {
		return errText(err)
	}
	return "ready"
}

func (f *matrixFixture) syncLines(t *testing.T) []string {
	t.Helper()
	var lines []string
	for _, tg := range f.daemonTargets() {
		res, err := nokkuv1connect.NewDaemonControlServiceClient(clientOn(
			f.srv,
			daemonAuth(t, f.cfg, tg.key, tg.token, nokkuv1connect.DaemonControlServiceSyncDaemonProcedure),
		)).SyncDaemon(t.Context(), &nokkuv1.SyncDaemonRequest{})
		prefix := "SyncDaemon " + tg.label
		if err != nil {
			lines = append(lines, prefix+": "+errText(err))
			continue
		}
		lines = append(lines,
			prefix+": status "+strings.ToLower(strings.TrimPrefix(res.GetStatus().String(), "DAEMON_STATUS_")),
			prefix+": ca key "+f.key(res.GetUserCaPublicKey())+", host ca key "+f.key(res.GetHostCaPublicKey()),
		)
		lines = append(lines, f.principalLines(prefix, res.GetPrincipals())...)
	}
	return lines
}

func (f *matrixFixture) principalLines(prefix string, principals []*nokkuv1.AccountPrincipals) []string {
	if len(principals) == 0 {
		return []string{prefix + ": no principals"}
	}
	lines := make([]string, 0, len(principals))
	for _, p := range principals {
		lines = append(lines, prefix+" "+p.GetUsername()+": "+f.list(p.GetCertPrincipals()))
	}
	return lines
}

func (f *matrixFixture) selfAccessLines(t *testing.T) []string {
	t.Helper()
	var lines []string
	for _, c := range f.callers {
		prefix := "GetSubjectAccess of self as " + c.label
		res, err := nokkuv1connect.NewTargetServiceClient(f.as(c.token)).GetSubjectAccess(t.Context(),
			&nokkuv1.GetSubjectAccessRequest{})
		if err != nil {
			lines = append(lines, prefix+": "+errText(err))
			continue
		}
		subject := "user " + res.GetUser().GetId()
		if res.GetServiceAccount() != nil {
			subject = "service account " + res.GetServiceAccount().GetId()
		}
		lines = append(lines, prefix+": subject "+subject, prefix+": cas "+f.list(caIDs(res)))
		lines = append(lines, f.targetAccessLines(prefix, res.GetTargets())...)
	}
	return lines
}

func (f *matrixFixture) subjectAccessLines(t *testing.T) []string {
	t.Helper()
	admin := nokkuv1connect.NewTargetServiceClient(f.adminClient())
	var lines []string
	for _, s := range f.subjects {
		lines = append(lines, f.subjectAccess(t, "GetSubjectAccess by admin of "+s.label, admin, s.id)...)
	}
	// A member reads its own access, and its team is another subject.
	byID := map[string]string{}
	for _, s := range f.subjects {
		byID[s.label] = s.id
	}
	for _, c := range f.callers[:2] {
		member := nokkuv1connect.NewTargetServiceClient(f.as(c.token))
		prefix := "GetSubjectAccess by " + c.label + " of " + c.label
		lines = append(lines, f.subjectAccess(t, prefix, member, byID[c.label])...)
	}
	member := nokkuv1connect.NewTargetServiceClient(f.as(f.callers[1].token))
	lines = append(lines, f.subjectAccess(t, "GetSubjectAccess by bob of staff", member, byID["staff"])...)
	return lines
}

func (f *matrixFixture) subjectAccess(
	t *testing.T,
	prefix string,
	client nokkuv1connect.TargetServiceClient,
	subjectID string,
) []string {
	t.Helper()
	res, err := client.GetSubjectAccess(t.Context(), &nokkuv1.GetSubjectAccessRequest{SubjectId: &subjectID})
	if err != nil {
		return []string{prefix + ": " + errText(err)}
	}
	daemons := make([]string, 0, len(res.GetDaemons()))
	for _, d := range res.GetDaemons() {
		daemons = append(daemons, d.GetId())
	}
	lines := []string{prefix + ": daemons " + f.list(daemons), prefix + ": cas " + f.list(caIDs(res))}
	return append(lines, f.targetAccessLines(prefix, res.GetTargets())...)
}

// caIDs is empty for a subject with no targets, the answer carries no CA then.
func caIDs(res *nokkuv1.GetSubjectAccessResponse) []string {
	if ca := res.GetCertificateAuthority(); ca != nil {
		return []string{ca.GetId()}
	}
	return []string{}
}

func (f *matrixFixture) targetAccessLines(prefix string, targets []*nokkuv1.Target) []string {
	if len(targets) == 0 {
		return []string{prefix + ": no targets"}
	}
	lines := make([]string, 0, len(targets))
	for _, tg := range targets {
		expiring := slices.Collect(maps.Keys(tg.GetUsernameExpiresAt()))
		line := fmt.Sprintf("%s %s: accounts %s, expiring %s",
			prefix, tg.GetId(), f.list(tg.GetUsernames()), f.list(expiring))
		if tg.Blocked != nil {
			line += ", blocked " + strings.ToLower(strings.TrimPrefix(tg.GetBlocked().String(), "ACCESS_BLOCK_"))
		}
		lines = append(lines, line)
	}
	return lines
}

// reportLines asks an enterprise server, the shared one's plan has no report.
func (f *matrixFixture) reportLines(t *testing.T) []string {
	t.Helper()
	req := &nokkuv1.ExportAccessReportRequest{Format: nokkuv1.ExportAuditLogsRequest_FORMAT_JSON.Enum()}
	var lines []string
	restore := withoutAPlan(t, f.cfg)
	if _, err := nokkuv1connect.NewUtilServiceClient(f.adminClient()).ExportAccessReport(t.Context(), req); err != nil {
		// Hosted has no free plan, its refusal names the plan that ran out.
		refused := strings.ReplaceAll(errText(err), "inactive", "Community")
		lines = append(lines, "ExportAccessReport on community: "+refused)
	}
	restore()
	_, srv := enterprise(t)
	res, err := nokkuv1connect.NewUtilServiceClient(
		clientOn(srv, f.admin),
	).ExportAccessReport(t.Context(), req)
	if err != nil {
		return append(lines, "ExportAccessReport: "+errText(err))
	}
	var rows []matrixReportRow
	require.NoError(t, json.Unmarshal(res.GetData(), &rows))
	for _, r := range rows {
		target, ok := f.labels[r.Target]
		if !ok || !slices.ContainsFunc(f.targets, func(tg matrixTarget) bool { return tg.label == target }) {
			continue
		}
		lines = append(lines, fmt.Sprintf(
			"ExportAccessReport %s %s %s %s: via %s, active %t, expires %s, last certificate %s, enforced %t, stale %t",
			target, r.Account, r.Kind, r.SubjectID, cmp.Or(r.Via, "-"), r.Active,
			setOrNone(r.ExpiresAt), setOrNone(r.LastCertificateAt), r.Enforced, r.Stale,
		))
	}
	return lines
}

func (f *matrixFixture) daemonTargets() []matrixTarget {
	return slices.DeleteFunc(slices.Clone(f.targets), func(tg matrixTarget) bool { return tg.daemonID == "" })
}

func (f *matrixFixture) scrub(s string) string {
	return f.replacer.Replace(s)
}

// list scrubs before it sorts, raw ids would sort differently on every run.
func (f *matrixFixture) list(items []string) string {
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = f.scrub(item)
	}
	slices.Sort(out)
	return "[" + strings.Join(out, " ") + "]"
}

func (f *matrixFixture) key(key string) string {
	if key == "" {
		return "none"
	}
	return f.scrub(strings.TrimSpace(key))
}

func (f *matrixFixture) conn(interceptors ...connect.ClientInterceptor) *connect.Client {
	return clientOn(f.srv, interceptors...)
}

func (f *matrixFixture) as(token string) *connect.Client {
	return f.conn(header("Authorization", "Bearer "+token))
}

func (f *matrixFixture) adminClient() *connect.Client {
	return f.conn(f.admin)
}

func setOrNone(at *time.Time) string {
	if at == nil {
		return "none"
	}
	return "set"
}
