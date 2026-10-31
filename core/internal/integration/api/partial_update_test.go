//go:build integration

package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"image"
	imgpng "image/png"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
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

// partialField is one field of a resource as read back, by dotted name. An empty value is unset or empty.
type partialField struct {
	name, value string
}

// partialCase sends an update that sets one field, or only the id for "nothing".
type partialCase struct {
	field  string
	update func(id string) error
}

// partialResource makes a fresh resource for every case, so each case starts from the same baseline.
type partialResource struct {
	rpc    string
	create func() string
	read   func(id string) []partialField
	// drop removes a resource right after its case, for resources the workspace holds only a few of.
	drop  func(id string)
	cases []partialCase
}

// TestPartialUpdates pins what each update does to the fields it was not sent. Every field starts out set, the
// update sets one, and every field is compared with what it was before.
func TestPartialUpdates(t *testing.T) {
	cfg, srv := newTestAPI(t)
	admin := partialConn(srv, seedMember(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN))
	// The idle timeout and audit streams are paid features, the shared test server runs on Community.
	_, paid := enterprise(t)

	var lines []string
	for _, r := range []partialResource{
		partialAccount(t, cfg, srv),
		partialCA(t, admin),
		partialDaemon(t, cfg, srv, admin),
		partialWorkspace(t, cfg, paid),
		partialTeam(t, cfg, admin),
		partialTarget(t, admin),
		partialAuditStream(t, cfg, paid),
		partialServiceAccount(t, admin),
	} {
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

// partialFields flattens m, nested messages by dotted name. Timestamps and durations stay one field.
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
	return connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), header("Authorization", "Bearer "+token))
}

func partialAccount(t *testing.T, cfg *config.Config, srv *httptest.Server) partialResource {
	t.Helper()
	var png bytes.Buffer
	require.NoError(t, imgpng.Encode(&png, image.NewNRGBA(image.Rect(0, 0, 64, 64))))
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
			u := seedUser(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
			tokens[u.ID] = sessionFor(t, cfg, u)
			_, err := self(u.ID).SetAvatar(t.Context(), &nokkuv1.SetAvatarRequest{Image: png.Bytes()})
			require.NoError(t, err)
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
	listed, err := certs.ListCertificateAuthorities(t.Context(), &nokkuv1.ListCertificateAuthoritiesRequest{})
	require.NoError(t, err)
	var oldDefault string
	for _, ca := range listed.GetCertificateAuthorities() {
		if ca.GetIsDefault() {
			oldDefault = ca.GetId()
		}
	}
	var made []string
	// Each baseline CA takes the workspace default, so the old default gets it back before they go.
	t.Cleanup(func() {
		ctx := context.WithoutCancel(t.Context())
		if oldDefault != "" {
			_, err := certs.UpdateCertificateAuthority(ctx, masked(&nokkuv1.UpdateCertificateAuthorityRequest{
				Id: &oldDefault, IsDefault: new(true),
			}))
			require.NoError(t, err)
		}
		for _, id := range made {
			_, err := certs.DeleteCertificateAuthority(ctx, &nokkuv1.DeleteCertificateAuthorityRequest{Id: &id})
			require.NoError(t, err)
		}
	})
	update := func(req *nokkuv1.UpdateCertificateAuthorityRequest) func(string) error {
		return func(id string) error {
			req.Id = &id
			_, err := certs.UpdateCertificateAuthority(t.Context(), masked(req))
			return err
		}
	}
	return partialResource{
		rpc: "CertificateService.UpdateCertificateAuthority",
		create: func() string {
			res, err := certs.CreateCertificateAuthority(t.Context(), &nokkuv1.CreateCertificateAuthorityRequest{
				Name:           new(uniq("partial")),
				Description:    new("baseline"),
				IsDefault:      new(true),
				UserDefaultTtl: durationpb.New(time.Hour),
				UserMaxTtl:     durationpb.New(12 * time.Hour),
				HostTtl:        durationpb.New(24 * time.Hour),
				ForceCommand:   new("/usr/bin/baseline"),
				SourceAddress:  new("10.0.0.0/8"),
			})
			require.NoError(t, err)
			made = append(made, res.GetCertificateAuthority().GetId())
			return res.GetCertificateAuthority().GetId()
		},
		read: func(id string) []partialField {
			res, err := certs.GetCertificateAuthority(t.Context(), &nokkuv1.GetCertificateAuthorityRequest{Id: &id})
			require.NoError(t, err)
			return partialFields(res.GetCertificateAuthority(), "id")
		},
		cases: []partialCase{
			{"name", update(&nokkuv1.UpdateCertificateAuthorityRequest{Name: new(uniq("renamed"))})},
			{"description", update(&nokkuv1.UpdateCertificateAuthorityRequest{Description: new("changed")})},
			{"is_default", update(&nokkuv1.UpdateCertificateAuthorityRequest{IsDefault: new(false)})},
			{"user_default_ttl", update(&nokkuv1.UpdateCertificateAuthorityRequest{
				UserDefaultTtl: durationpb.New(2 * time.Hour),
			})},
			{"user_max_ttl", update(&nokkuv1.UpdateCertificateAuthorityRequest{
				UserMaxTtl: durationpb.New(10 * time.Hour),
			})},
			{"host_ttl", update(&nokkuv1.UpdateCertificateAuthorityRequest{
				HostTtl: durationpb.New(48 * time.Hour),
			})},
			{"force_command", update(&nokkuv1.UpdateCertificateAuthorityRequest{ForceCommand: new("/usr/bin/other")})},
			{"source_address", update(&nokkuv1.UpdateCertificateAuthorityRequest{SourceAddress: new("192.0.2.0/24")})},
			{"nothing", update(&nokkuv1.UpdateCertificateAuthorityRequest{})},
		},
	}
}

// partialDaemon starts pending with every switch away from its default. Ephemeral comes from the join token and
// idle_timeout from the workspace, an update ignores both.
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
			_, enrolled := enrollTestDaemon(t, cfg, srv, seedWorkspace(t, cfg), false)
			// Its server is on partialCA's default, which goes at the end. A CA in use cannot be deleted.
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

// partialWorkspace works on the one shared workspace, every case starts from the same baseline and the workspace
// gets back what it had. enforce_sso stays off, turning it on ends every session that did not come from SSO.
func partialWorkspace(t *testing.T, cfg *config.Config, srv *httptest.Server) partialResource {
	t.Helper()
	ws := seedWorkspace(t, cfg)
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
	return partialResource{
		rpc: "WorkspaceService.UpdateWorkspace",
		create: func() string {
			restoreWorkspace(t.Context(), t, cfg, original)
			_, err := owner.UpdateWorkspace(t.Context(), masked(&nokkuv1.UpdateWorkspaceRequest{
				Name:        new("partial baseline"),
				Description: new("baseline"),
				Settings: &nokkuv1.WorkspaceSettings{
					DefaultDaemonConfig: &nokkuv1.DaemonConfig{
						RecordSessions:       new(false),
						AllowForwarding:      new(false),
						AllowAgentForwarding: new(false),
						GatewayPorts:         new(true),
						Ephemeral:            new(true),
					},
					SessionIdleTimeout: durationpb.New(10 * time.Minute),
				},
			}))
			require.NoError(t, err)
			inWorkspace(t, cfg, ws, func(q *db.Queries) error {
				return q.SetRequestableTags(t.Context(), []string{"prod", "web"})
			})
			return ws
		},
		read: func(string) []partialField {
			res, err := owner.GetWorkspace(t.Context(), &nokkuv1.GetWorkspaceRequest{})
			require.NoError(t, err)
			// The API never shows requestable_tags, the row does.
			var row *db.Workspace
			inWorkspace(t, cfg, ws, func(q *db.Queries) (err error) {
				row, err = q.GetWorkspace(t.Context())
				return err
			})
			return append(partialFields(res.GetWorkspace(), "id", "requestable_tags"),
				partialField{"requestable_tags (stored)", strings.Join(row.RequestableTags, "\x00")})
		},
		cases: []partialCase{
			{"name", update(&nokkuv1.UpdateWorkspaceRequest{Name: new("partial renamed")})},
			{"description", update(&nokkuv1.UpdateWorkspaceRequest{Description: new("changed")})},
			{"settings.default_daemon_config.record_sessions", update(&nokkuv1.UpdateWorkspaceRequest{
				Settings: &nokkuv1.WorkspaceSettings{
					DefaultDaemonConfig: &nokkuv1.DaemonConfig{RecordSessions: new(true)},
				},
			})},
			{"settings.session_idle_timeout", update(&nokkuv1.UpdateWorkspaceRequest{
				Settings: &nokkuv1.WorkspaceSettings{SessionIdleTimeout: durationpb.New(20 * time.Minute)},
			})},
			{"nothing", update(&nokkuv1.UpdateWorkspaceRequest{})},
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
	// The query keeps a description it is not given, only the owner role puts the NULL back.
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
			member := seedUser(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
			inWorkspace(t, cfg, seedWorkspace(t, cfg), func(q *db.Queries) error {
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
			{"nothing", update(&nokkuv1.UpdateTeamRequest{})},
		},
	}
}

func partialTarget(t *testing.T, admin *connect.Client) partialResource {
	t.Helper()
	certs := nokkuv1connect.NewCertificateServiceClient(admin)
	targets := nokkuv1connect.NewTargetServiceClient(admin)
	newCA := func() string {
		res, err := certs.CreateCertificateAuthority(t.Context(), &nokkuv1.CreateCertificateAuthorityRequest{
			Name: new(uniq("partial-target")),
		})
		require.NoError(t, err)
		id := res.GetCertificateAuthority().GetId()
		t.Cleanup(func() {
			_, err := certs.DeleteCertificateAuthority(context.WithoutCancel(t.Context()),
				&nokkuv1.DeleteCertificateAuthorityRequest{Id: &id})
			require.NoError(t, err)
		})
		return id
	}
	baseCA, otherCA := newCA(), newCA()
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
				CaId:          &baseCA,
				Name:          new(uniq("partial")),
				Description:   new("baseline"),
				HostPublicKey: new(partialHostKey(t)),
				Endpoints:     []string{"10.0.0.1:22", "10.0.0.2:22"},
				Tags:          []string{"prod", "web"},
			})
			require.NoError(t, err)
			id := res.GetTarget().GetId()
			// Before its CAs go, a CA in use cannot be deleted.
			t.Cleanup(func() {
				_, err := targets.DeleteTarget(
					context.WithoutCancel(t.Context()),
					&nokkuv1.DeleteTargetRequest{Id: &id},
				)
				require.NoError(t, err)
			})
			return id
		},
		read: func(id string) []partialField {
			res, err := targets.GetTarget(t.Context(), &nokkuv1.GetTargetRequest{Id: &id})
			require.NoError(t, err)
			return partialFields(res.GetTarget(), "id")
		},
		cases: []partialCase{
			{"ca_id", update(&nokkuv1.UpdateTargetRequest{CaId: &otherCA})},
			{"name", update(&nokkuv1.UpdateTargetRequest{Name: new(uniq("renamed"))})},
			{"description", update(&nokkuv1.UpdateTargetRequest{Description: new("changed")})},
			{"host_public_key", update(&nokkuv1.UpdateTargetRequest{HostPublicKey: new(partialHostKey(t))})},
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

// partialAuditStream leaves out the delivery state, it changes on its own. The secret is read from the row since the
// API never shows it.
func partialAuditStream(t *testing.T, cfg *config.Config, srv *httptest.Server) partialResource {
	t.Helper()
	ws := seedWorkspace(t, cfg)
	streams := nokkuv1connect.NewAuditStreamServiceClient(
		partialConn(srv, seedMember(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER)),
	)
	drop := func(id string) {
		_, _ = streams.DeleteAuditStream(context.WithoutCancel(t.Context()), &nokkuv1.DeleteAuditStreamRequest{Id: &id})
	}
	// The stream tests clean up with t.Context(), which is cancelled by then, so their streams stay and fill the cap.
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
				Name:        new(uniq("partial")),
				Description: new("baseline"),
				Role:        nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR.Enum(),
				Tags:        []string{"prod", "web"},
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
			{"nothing", update(&nokkuv1.UpdateServiceAccountRequest{})},
		},
	}
}

// Two tabs saving different settings at once keep both, the update reads the row under a lock.
func TestConcurrentSettingsKeepBoth(t *testing.T) {
	cfg, _ := newTestAPI(t)
	_, srv := enterprise(t)
	ws := seedWorkspace(t, cfg)
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
			_, err := owner.UpdateWorkspace(t.Context(), masked(&nokkuv1.UpdateWorkspaceRequest{
				Settings: &nokkuv1.WorkspaceSettings{SessionIdleTimeout: durationpb.New(timeout)},
			}))
			errs <- err
		}()
		go func() {
			_, err := owner.UpdateWorkspace(t.Context(), masked(&nokkuv1.UpdateWorkspaceRequest{
				Settings: &nokkuv1.WorkspaceSettings{
					DefaultDaemonConfig: &nokkuv1.DaemonConfig{RecordSessions: new(record)},
				},
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
