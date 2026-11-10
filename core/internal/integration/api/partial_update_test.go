//go:build integration

package api_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// partialField is a field as read back, by dotted name. "" is unset or empty.
type partialField struct {
	name, value string
}

// partialCase updates one field, or sends only the id for "nothing".
type partialCase struct {
	field  string
	update func(id string) error
}

// partialResource makes a fresh resource per case, for the same baseline.
type partialResource struct {
	rpc    string
	create func() string
	read   func(id string) []partialField
	// drop removes it after its case, where the workspace holds only a few.
	drop  func(id string)
	cases []partialCase
}

// TestPartialUpdates pins what each update does to the fields it was not sent.
func TestPartialUpdates(t *testing.T) {
	cfg, _ := newTestAPI(t)
	// Idle timeout and audit streams are paid, the shared server has neither.
	_, srv := enterprise(t)
	admin := partialConn(srv, seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN))

	resources := []partialResource{
		partialAccount(t, cfg, srv),
		partialCA(t, admin),
		partialDaemon(t, cfg, srv, admin),
	}
	resources = append(resources, partialWorkspace(t, cfg, srv)...)
	resources = append(resources,
		partialTeam(t, cfg, admin),
		partialTarget(t, admin),
		partialAuditStream(t, cfg, srv),
		partialServiceAccount(t, admin),
	)

	var lines []string
	for _, r := range resources {
		lines = append(lines, r.record(t)...)
	}
	assertGolden(t, "partial_update.golden", lines)
}

func (r partialResource) record(t *testing.T) []string {
	t.Helper()
	var lines []string
	for i, c := range r.cases {
		id := r.create()
		before := r.read(id)
		if i == 0 {
			var empty []string
			for _, f := range before {
				if f.value == "" {
					empty = append(empty, f.name)
				}
			}
			lines = append(lines, fmt.Sprintf("%s baseline: empty %v", r.rpc, empty))
		}
		prefix := r.rpc + " sets " + c.field
		if err := c.update(id); err != nil {
			lines = append(lines, prefix+": "+errText(err))
		}
		after := r.read(id)
		require.Len(t, after, len(before))
		for j, b := range before {
			lines = append(lines, prefix+": "+b.name+" "+partialStatus(b.value, after[j].value))
		}
		if r.drop != nil {
			r.drop(id)
		}
	}
	return lines
}

func partialStatus(before, after string) string {
	switch {
	case before == after:
		return "kept"
	case after == "":
		return "cleared"
	}
	return "changed"
}

// partialFields flattens m by dotted name, timestamps and durations stay whole.
func partialFields(m proto.Message, skip ...string) []partialField {
	return flattenPartial("", m.ProtoReflect(), skip)
}

func flattenPartial(prefix string, m protoreflect.Message, skip []string) []partialField {
	var out []partialField
	fields := m.Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		name := prefix + string(fd.Name())
		if slices.Contains(skip, name) {
			continue
		}
		if fd.Message() != nil && !fd.IsList() && !fd.IsMap() && fd.Message().FullName().Parent() != "google.protobuf" {
			out = append(out, flattenPartial(name+".", m.Get(fd).Message(), skip)...)
			continue
		}
		out = append(out, partialField{name, partialValue(m, fd)})
	}
	return out
}

func partialValue(m protoreflect.Message, fd protoreflect.FieldDescriptor) string {
	if !m.Has(fd) {
		return ""
	}
	v := m.Get(fd)
	var parts []string
	switch {
	case fd.IsList():
		for i := range v.List().Len() {
			parts = append(parts, encodePartial(fd, v.List().Get(i)))
		}
	case fd.IsMap():
		v.Map().Range(func(k protoreflect.MapKey, mv protoreflect.Value) bool {
			parts = append(parts, k.String()+"="+encodePartial(fd.MapValue(), mv))
			return true
		})
		slices.Sort(parts)
	default:
		return encodePartial(fd, v)
	}
	return strings.Join(parts, "\x00")
}

func encodePartial(fd protoreflect.FieldDescriptor, v protoreflect.Value) string {
	if fd.Message() == nil {
		return fmt.Sprint(v.Interface())
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(v.Message().Interface())
	if err != nil {
		return "unencodable: " + err.Error()
	}
	return string(b)
}

func partialConn(srv *httptest.Server, token string) *connect.Client {
	return clientOn(srv, header("Authorization", "Bearer "+token))
}

func partialAccount(t *testing.T, cfg *config.Config, srv *httptest.Server) partialResource {
	t.Helper()
	tokens := map[string]string{}
	self := func(id string) nokkuv1connect.AccountServiceClient {
		return nokkuv1connect.NewAccountServiceClient(partialConn(srv, tokens[id]))
	}
	update := func(req *nokkuv1.UpdateAccountRequest) func(string) error {
		return func(id string) error {
			_, err := self(id).UpdateAccount(t.Context(), masked(req))
			return err
		}
	}
	return partialResource{
		rpc: "AccountService.UpdateAccount",
		create: func() string {
			ws := testWorkspace.ID
			u := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
			tokens[u.ID] = sessionFor(t, cfg, u)
			inWorkspace(t, cfg, ws, func(q *db.Queries) error {
				_, err := q.UpdateUser(
					t.Context(),
					&db.UpdateUserParams{ID: u.ID, Picture: new("https://idp.test/u.png")},
				)
				return err
			})
			return u.ID
		},
		read: func(id string) []partialField {
			res, err := self(id).GetAccount(t.Context(), &nokkuv1.GetAccountRequest{})
			require.NoError(t, err)
			return partialFields(res.GetUser(), "id")
		},
		cases: []partialCase{
			{"name", update(&nokkuv1.UpdateAccountRequest{Name: new("renamed")})},
			{"nothing", update(&nokkuv1.UpdateAccountRequest{})},
		},
	}
}

func partialCA(t *testing.T, admin *connect.Client) partialResource {
	t.Helper()
	certs := nokkuv1connect.NewCertificateServiceClient(admin)
	read := func() *nokkuv1.CertificateAuthority {
		res, err := certs.GetCertificateAuthority(t.Context(), &nokkuv1.GetCertificateAuthorityRequest{})
		require.NoError(t, err)
		return res.GetCertificateAuthority()
	}
	// Other tests roll the shared CA over, so do it here too for one baseline.
	_, err := certs.RolloverCertificateAuthority(t.Context(), &nokkuv1.RolloverCertificateAuthorityRequest{})
	require.NoError(t, err)
	// One CA, so each case sets the baseline and the test restores it.
	before := read()
	t.Cleanup(func() {
		_, err := certs.UpdateCertificateAuthority(context.WithoutCancel(t.Context()),
			masked(&nokkuv1.UpdateCertificateAuthorityRequest{
				UserTtl:       before.GetUserTtl(),
				SourceAddress: new(before.GetSourceAddress()),
			}))
		require.NoError(t, err)
	})
	update := func(req *nokkuv1.UpdateCertificateAuthorityRequest) func(string) error {
		return func(string) error {
			_, err := certs.UpdateCertificateAuthority(t.Context(), masked(req))
			return err
		}
	}
	return partialResource{
		rpc: "CertificateService.UpdateCertificateAuthority",
		create: func() string {
			res, err := certs.UpdateCertificateAuthority(t.Context(), masked(&nokkuv1.UpdateCertificateAuthorityRequest{
				UserTtl:       durationpb.New(time.Hour),
				SourceAddress: new("10.0.0.0/8"),
			}))
			require.NoError(t, err)
			return res.GetCertificateAuthority().GetId()
		},
		read: func(string) []partialField { return partialFields(read(), "id") },
		cases: []partialCase{
			{"user_ttl", update(&nokkuv1.UpdateCertificateAuthorityRequest{UserTtl: durationpb.New(2 * time.Hour)})},
			{"source_address", update(&nokkuv1.UpdateCertificateAuthorityRequest{SourceAddress: new("192.0.2.0/24")})},
			{"nothing", update(&nokkuv1.UpdateCertificateAuthorityRequest{})},
		},
	}
}

// partialDaemon starts pending with every switch away from its default. An
// update ignores ephemeral and idle_timeout.
func partialDaemon(t *testing.T, cfg *config.Config, srv *httptest.Server, admin *connect.Client) partialResource {
	t.Helper()
	daemons := nokkuv1connect.NewDaemonServiceClient(admin)
	update := func(req *nokkuv1.UpdateDaemonRequest) func(string) error {
		return func(id string) error {
			req.Id = &id
			_, err := daemons.UpdateDaemon(t.Context(), masked(req))
			return err
		}
	}
	return partialResource{
		rpc: "DaemonService.UpdateDaemon",
		create: func() string {
			_, enrolled := enrollTestDaemon(t, cfg, srv, testWorkspace.ID, false)
			t.Cleanup(func() {
				_, err := daemons.DeleteDaemon(context.WithoutCancel(t.Context()),
					&nokkuv1.DeleteDaemonRequest{Id: enrolled.Id})
				require.NoError(t, err)
			})
			_, err := daemons.UpdateDaemon(t.Context(), masked(&nokkuv1.UpdateDaemonRequest{
				Id: enrolled.Id,
				Config: &nokkuv1.DaemonConfig{
					RecordSessions:       new(false),
					AllowForwarding:      new(false),
					AllowAgentForwarding: new(false),
					GatewayPorts:         new(true),
				},
			}))
			require.NoError(t, err)
			return enrolled.GetId()
		},
		read: func(id string) []partialField {
			res, err := daemons.GetDaemon(t.Context(), &nokkuv1.GetDaemonRequest{Id: &id})
			require.NoError(t, err)
			return partialFields(res.GetDaemon(), "id")
		},
		cases: []partialCase{
			{"status", update(&nokkuv1.UpdateDaemonRequest{
				Status: nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED.Enum(),
			})},
			{"config.allow_forwarding", update(&nokkuv1.UpdateDaemonRequest{
				Config: &nokkuv1.DaemonConfig{AllowForwarding: new(true)},
			})},
			{"nothing", update(&nokkuv1.UpdateDaemonRequest{})},
		},
	}
}

// partialWorkspace leaves enforce_sso off, and both calls on the workspace row share its baseline.
func partialWorkspace(t *testing.T, cfg *config.Config, srv *httptest.Server) []partialResource {
	t.Helper()
	ws := testWorkspace.ID
	owner := nokkuv1connect.NewWorkspaceServiceClient(
		partialConn(srv, seedMember(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER)),
	)
	var original *db.Workspace
	inWorkspace(t, cfg, ws, func(q *db.Queries) (err error) {
		original, err = q.GetWorkspace(t.Context())
		return err
	})
	t.Cleanup(func() { restoreWorkspace(context.WithoutCancel(t.Context()), t, cfg, original) })

	update := func(req *nokkuv1.UpdateWorkspaceRequest) func(string) error {
		return func(string) error {
			_, err := owner.UpdateWorkspace(t.Context(), masked(req))
			return err
		}
	}
	defaults := func(req *nokkuv1.UpdateDaemonDefaultsRequest) func(string) error {
		return func(string) error {
			_, err := owner.UpdateDaemonDefaults(t.Context(), masked(req))
			return err
		}
	}
	create := func() string {
		restoreWorkspace(t.Context(), t, cfg, original)
		_, err := owner.UpdateWorkspace(t.Context(), masked(&nokkuv1.UpdateWorkspaceRequest{
			Name:        new("partial baseline"),
			Description: new("baseline"),
		}))
		require.NoError(t, err)
		_, err = owner.UpdateDaemonDefaults(t.Context(), masked(&nokkuv1.UpdateDaemonDefaultsRequest{
			DefaultDaemonConfig: &nokkuv1.DaemonConfig{
				RecordSessions:       new(false),
				AllowForwarding:      new(false),
				AllowAgentForwarding: new(false),
				GatewayPorts:         new(true),
			},
			SessionIdleTimeout: durationpb.New(10 * time.Minute),
		}))
		require.NoError(t, err)
		inWorkspace(t, cfg, ws, func(q *db.Queries) error {
			return q.SetRequestableTags(t.Context(), []string{"prod", "web"})
		})
		return ws
	}
	read := func(string) []partialField {
		res, err := owner.GetWorkspace(t.Context(), &nokkuv1.GetWorkspaceRequest{})
		require.NoError(t, err)
		// requestable_tags is checked on the row, the one access requests match against.
		var row *db.Workspace
		inWorkspace(t, cfg, ws, func(q *db.Queries) (err error) {
			row, err = q.GetWorkspace(t.Context())
			return err
		})
		return append(partialFields(res.GetWorkspace(), "id", "requestable_tags"),
			partialField{"requestable_tags (stored)", strings.Join(row.RequestableTags, "\x00")})
	}
	return []partialResource{
		{
			rpc:    "WorkspaceService.UpdateWorkspace",
			create: create,
			read:   read,
			cases: []partialCase{
				{"name", update(&nokkuv1.UpdateWorkspaceRequest{Name: new("partial renamed")})},
				{"description", update(&nokkuv1.UpdateWorkspaceRequest{Description: new("changed")})},
				{"nothing", update(&nokkuv1.UpdateWorkspaceRequest{})},
			},
		},
		{
			rpc:    "WorkspaceService.UpdateDaemonDefaults",
			create: create,
			read:   read,
			cases: []partialCase{
				{"default_daemon_config.record_sessions", defaults(&nokkuv1.UpdateDaemonDefaultsRequest{
					DefaultDaemonConfig: &nokkuv1.DaemonConfig{RecordSessions: new(true)},
				})},
				{"session_idle_timeout", defaults(&nokkuv1.UpdateDaemonDefaultsRequest{
					SessionIdleTimeout: durationpb.New(20 * time.Minute),
				})},
				{"nothing", defaults(&nokkuv1.UpdateDaemonDefaultsRequest{})},
			},
		},
	}
}

func restoreWorkspace(ctx context.Context, t *testing.T, cfg *config.Config, w *db.Workspace) {
	t.Helper()
	ctx = actor.WithWorkspace(ctx, actor.Workspace{ID: w.ID})
	require.NoError(t, cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		if _, err := q.UpdateWorkspace(ctx, &db.UpdateWorkspaceParams{
			Name:        &w.Name,
			Description: w.Description,
			Settings:    w.Settings,
		}); err != nil {
			return err
		}
		return q.SetRequestableTags(ctx, w.RequestableTags)
	}))
	if w.Description != nil {
		return
	}
	// The query can't set NULL, the owner role can.
	owner, err := pgx.Connect(ctx, "")
	require.NoError(t, err)
	_, err = owner.Exec(ctx, "UPDATE workspaces SET description = NULL WHERE id = $1", w.ID)
	require.NoError(t, err)
	require.NoError(t, owner.Close(ctx))
}

func partialTeam(t *testing.T, cfg *config.Config, admin *connect.Client) partialResource {
	t.Helper()
	teams := nokkuv1connect.NewTeamServiceClient(admin)
	update := func(req *nokkuv1.UpdateTeamRequest) func(string) error {
		return func(id string) error {
			req.Id = &id
			_, err := teams.UpdateTeam(t.Context(), masked(req))
			return err
		}
	}
	return partialResource{
		rpc: "TeamService.UpdateTeam",
		create: func() string {
			res, err := teams.CreateTeam(t.Context(), &nokkuv1.CreateTeamRequest{
				Name:        new(uniq("partial")),
				Description: new("baseline"),
				Tags:        []string{"prod", "web"},
			})
			require.NoError(t, err)
			id := res.GetTeam().GetId()
			member := seedUser(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
			inWorkspace(t, cfg, testWorkspace.ID, func(q *db.Queries) error {
				return q.AddTeamMember(t.Context(), &db.AddTeamMemberParams{UserID: member.ID, TeamID: id})
			})
			return id
		},
		read: func(id string) []partialField {
			res, err := teams.GetTeam(t.Context(), &nokkuv1.GetTeamRequest{Id: &id})
			require.NoError(t, err)
			return partialFields(res.GetTeam(), "id")
		},
		cases: []partialCase{
			{"name", update(&nokkuv1.UpdateTeamRequest{Name: new(uniq("renamed"))})},
			{"description", update(&nokkuv1.UpdateTeamRequest{Description: new("changed")})},
			{"tags", update(&nokkuv1.UpdateTeamRequest{Tags: []string{"staging"}})},
			{
				"tags to none",
				update(&nokkuv1.UpdateTeamRequest{UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"tags"}}}),
			},
			{"scim_open", update(&nokkuv1.UpdateTeamRequest{ScimOpen: new(true)})},
			{"nothing", update(&nokkuv1.UpdateTeamRequest{})},
		},
	}
}

func partialTarget(t *testing.T, admin *connect.Client) partialResource {
	t.Helper()
	targets := nokkuv1connect.NewTargetServiceClient(admin)
	update := func(req *nokkuv1.UpdateTargetRequest) func(string) error {
		return func(id string) error {
			req.Id = &id
			_, err := targets.UpdateTarget(t.Context(), masked(req))
			return err
		}
	}
	return partialResource{
		rpc: "TargetService.UpdateTarget",
		create: func() string {
			res, err := targets.CreateTarget(t.Context(), &nokkuv1.CreateTargetRequest{
				Name:          new(uniq("partial")),
				Description:   new("baseline"),
				HostPublicKey: new(partialHostKey(t)),
				Endpoints:     []string{"10.0.0.1:22", "10.0.0.2:22"},
				Tags:          []string{"prod", "web"},
			})
			require.NoError(t, err)
			return res.GetTarget().GetId()
		},
		read: func(id string) []partialField {
			res, err := targets.GetTarget(t.Context(), &nokkuv1.GetTargetRequest{Id: &id})
			require.NoError(t, err)
			return partialFields(res.GetTarget(), "id")
		},
		cases: []partialCase{
			{"name", update(&nokkuv1.UpdateTargetRequest{Name: new(uniq("renamed"))})},
			{"description", update(&nokkuv1.UpdateTargetRequest{Description: new("changed")})},
			{"endpoints", update(&nokkuv1.UpdateTargetRequest{Endpoints: []string{"10.0.0.3:22"}})},
			{"tags", update(&nokkuv1.UpdateTargetRequest{Tags: []string{"staging"}})},
			{
				"tags to none",
				update(&nokkuv1.UpdateTargetRequest{UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"tags"}}}),
			},
			{
				"endpoints to none",
				update(&nokkuv1.UpdateTargetRequest{UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"endpoints"}}}),
			},
			{"nothing", update(&nokkuv1.UpdateTargetRequest{})},
		},
	}
}

func partialHostKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := gossh.NewPublicKey(pub)
	require.NoError(t, err)
	return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(sshPub)))
}

// partialAuditStream skips delivery state. The secret comes from the row.
func partialAuditStream(t *testing.T, cfg *config.Config, srv *httptest.Server) partialResource {
	t.Helper()
	ws := testWorkspace.ID
	streams := nokkuv1connect.NewAuditStreamServiceClient(
		partialConn(srv, seedMember(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER)),
	)
	drop := func(id string) {
		_, _ = streams.DeleteAuditStream(context.WithoutCancel(t.Context()), &nokkuv1.DeleteAuditStreamRequest{Id: &id})
	}
	// A stream another test left would count against the cap.
	leftover, err := streams.ListAuditStreams(t.Context(), &nokkuv1.ListAuditStreamsRequest{})
	require.NoError(t, err)
	for _, s := range leftover.GetStreams() {
		drop(s.GetId())
	}
	update := func(req *nokkuv1.UpdateAuditStreamRequest) func(string) error {
		return func(id string) error {
			req.Id = &id
			_, err := streams.UpdateAuditStream(t.Context(), masked(req))
			return err
		}
	}
	return partialResource{
		rpc: "AuditStreamService.UpdateAuditStream",
		create: func() string {
			res, err := streams.CreateAuditStream(t.Context(), &nokkuv1.CreateAuditStreamRequest{
				Kind:   nokkuv1.AuditStreamKind_AUDIT_STREAM_KIND_SPLUNK.Enum(),
				Url:    new("https://siem-baseline.invalid/collector"),
				Secret: new("baseline-secret"),
			})
			require.NoError(t, err)
			id := res.GetStream().GetId()
			t.Cleanup(func() { drop(id) })
			return id
		},
		read: func(id string) []partialField {
			res, err := streams.ListAuditStreams(t.Context(), &nokkuv1.ListAuditStreamsRequest{})
			require.NoError(t, err)
			i := slices.IndexFunc(res.GetStreams(), func(s *nokkuv1.AuditStream) bool { return s.GetId() == id })
			require.GreaterOrEqual(t, i, 0, "the stream is not listed")
			var secret string
			inWorkspace(t, cfg, ws, func(q *db.Queries) error {
				row, err := q.GetAuditStream(t.Context(), id)
				if err != nil {
					return err
				}
				plain, err := cfg.Keyset.Open(audit.SecretAAD(ws, id), row.Secret)
				secret = string(plain)
				return err
			})
			return append(partialFields(res.GetStreams()[i], "id", "last_sent_at", "last_error", "failing_since"),
				partialField{"secret (stored)", secret})
		},
		drop: drop,
		cases: []partialCase{
			{"url", update(&nokkuv1.UpdateAuditStreamRequest{Url: new("https://siem-moved.invalid/collector")})},
			{"secret", update(&nokkuv1.UpdateAuditStreamRequest{Secret: new("rotated-secret")})},
			{"enabled", update(&nokkuv1.UpdateAuditStreamRequest{Enabled: new(false)})},
			{"nothing", update(&nokkuv1.UpdateAuditStreamRequest{})},
		},
	}
}

func partialServiceAccount(t *testing.T, admin *connect.Client) partialResource {
	t.Helper()
	accounts := nokkuv1connect.NewServiceAccountServiceClient(admin)
	update := func(req *nokkuv1.UpdateServiceAccountRequest) func(string) error {
		return func(id string) error {
			req.Id = &id
			_, err := accounts.UpdateServiceAccount(t.Context(), masked(req))
			return err
		}
	}
	return partialResource{
		rpc: "ServiceAccountService.UpdateServiceAccount",
		create: func() string {
			res, err := accounts.CreateServiceAccount(t.Context(), &nokkuv1.CreateServiceAccountRequest{
				Name:          new(uniq("partial")),
				Description:   new("baseline"),
				Role:          nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR.Enum(),
				Tags:          []string{"prod", "web"},
				ForceCommand:  new("/usr/bin/baseline"),
				SourceAddress: new("10.0.0.0/8"),
			})
			require.NoError(t, err)
			return res.GetServiceAccount().GetId()
		},
		read: func(id string) []partialField {
			res, err := accounts.GetServiceAccount(t.Context(), &nokkuv1.GetServiceAccountRequest{Id: &id})
			require.NoError(t, err)
			return partialFields(res.GetServiceAccount(), "id")
		},
		cases: []partialCase{
			{"name", update(&nokkuv1.UpdateServiceAccountRequest{Name: new(uniq("renamed"))})},
			{"description", update(&nokkuv1.UpdateServiceAccountRequest{Description: new("changed")})},
			{"role", update(&nokkuv1.UpdateServiceAccountRequest{
				Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER.Enum(),
			})},
			{"tags", update(&nokkuv1.UpdateServiceAccountRequest{Tags: []string{"staging"}})},
			{
				"tags to none",
				update(
					&nokkuv1.UpdateServiceAccountRequest{UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"tags"}}},
				),
			},
			{"force_command", update(&nokkuv1.UpdateServiceAccountRequest{ForceCommand: new("/usr/bin/other")})},
			{"source_address", update(&nokkuv1.UpdateServiceAccountRequest{SourceAddress: new("192.0.2.0/24")})},
			{"nothing", update(&nokkuv1.UpdateServiceAccountRequest{})},
		},
	}
}

// Two tabs saving at once keep both, the update reads the row under a lock.
func TestConcurrentSettingsKeepBoth(t *testing.T) {
	cfg, _ := newTestAPI(t)
	_, srv := enterprise(t)
	ws := testWorkspace.ID
	owner := nokkuv1connect.NewWorkspaceServiceClient(
		partialConn(srv, seedMember(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER)),
	)
	var original *db.Workspace
	inWorkspace(t, cfg, ws, func(q *db.Queries) (err error) {
		original, err = q.GetWorkspace(t.Context())
		return err
	})
	t.Cleanup(func() { restoreWorkspace(context.WithoutCancel(t.Context()), t, cfg, original) })

	for round := range 20 {
		timeout := time.Duration(round+1) * time.Minute
		record := round%2 == 0
		errs := make(chan error, 2)
		go func() {
			_, err := owner.UpdateDaemonDefaults(t.Context(), masked(&nokkuv1.UpdateDaemonDefaultsRequest{
				SessionIdleTimeout: durationpb.New(timeout),
			}))
			errs <- err
		}()
		go func() {
			_, err := owner.UpdateDaemonDefaults(t.Context(), masked(&nokkuv1.UpdateDaemonDefaultsRequest{
				DefaultDaemonConfig: &nokkuv1.DaemonConfig{RecordSessions: new(record)},
			}))
			errs <- err
		}()
		require.NoError(t, <-errs)
		require.NoError(t, <-errs)

		res, err := owner.GetWorkspace(t.Context(), &nokkuv1.GetWorkspaceRequest{})
		require.NoError(t, err)
		settings := res.GetWorkspace().GetSettings()
		require.Equal(t, timeout, settings.GetSessionIdleTimeout().AsDuration(), "round %d lost the timeout", round)
		require.Equal(
			t,
			record,
			settings.GetDefaultDaemonConfig().GetRecordSessions(),
			"round %d lost the recording switch",
			round,
		)
	}
}
