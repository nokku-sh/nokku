package api

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"connectrpc.com/connect/v2"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/app"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/email"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
	"github.com/nokku-sh/nokku/core/internal/iam"
	"github.com/nokku-sh/nokku/core/internal/tenant"
)

const findMailTimeout = 30 * time.Second

// Only CreateWorkspace and FindWorkspaces run outside the workspace of the request's host.
type workspaceService struct {
	cfg *app.Config
}

func (s *workspaceService) GetWorkspace(
	ctx context.Context,
	_ *nokkuv1.GetWorkspaceRequest,
) (*nokkuv1.GetWorkspaceResponse, error) {
	workspace, err := s.cfg.Conn.Tenant().GetWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	ws, _ := actor.WorkspaceFromContext(ctx)
	// A failed lookup is Community, which leaves the banner out.
	st, _ := s.cfg.Entitlements.Status(ctx, ws.ID)
	resp := &nokkuv1.GetWorkspaceResponse{
		Workspace: workspace.ToProto(),
		BaseUrl:   new(ws.BaseURL),
		Inactive:  new(st.Plan.Name == entitlement.PlanInactive),
		Features:  featuresProto(st.Plan),
		Catalog:   catalogProto(),
		PlanNames: entitlement.PlanNames,
	}
	if st.Row != nil && s.cfg.SaaS {
		resp.DeleteAt = db.SafeTimestamp(deletionDate(st.Row))
	}
	return resp, nil
}

func (s *workspaceService) UpdateWorkspace(
	ctx context.Context,
	req *nokkuv1.UpdateWorkspaceRequest,
) (*nokkuv1.UpdateWorkspaceResponse, error) {
	workspace, err := s.cfg.Conn.Tenant().UpdateWorkspace(ctx, &db.UpdateWorkspaceParams{
		Name: req.Name, Description: req.Description,
	})
	if err != nil {
		return nil, err
	}
	return &nokkuv1.UpdateWorkspaceResponse{Workspace: workspace.ToProto()}, nil
}

func (s *workspaceService) SetEnforceSSO(
	ctx context.Context,
	req *nokkuv1.SetEnforceSSORequest,
) (*nokkuv1.SetEnforceSSOResponse, error) {
	audit.Set(ctx, "enforce_sso", req.GetEnforceSso())
	var workspace *db.Workspace
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		// Locked, so two tabs saving different settings at once keep both.
		base, err := q.GetWorkspaceForUpdate(ctx)
		if err != nil {
			return err
		}
		turnedOn := req.GetEnforceSso() && !base.Settings.GetEnforceSso()
		if turnedOn {
			// A provider nobody got through yet may be set up wrong, and only the owner would get back in.
			has, err := q.HasSSOSignIn(ctx)
			if err != nil {
				return err
			}
			if !has {
				return connect.NewError(
					connect.CodeFailedPrecondition,
					"sign in through a provider once before requiring single sign-on",
				)
			}
		}
		base.Settings = cmp.Or(base.Settings, &nokkuv1.WorkspaceSettings{})
		base.Settings.EnforceSso = req.EnforceSso
		workspace, err = q.UpdateWorkspace(ctx, &db.UpdateWorkspaceParams{Settings: base.Settings})
		if err != nil || !turnedOn {
			return err
		}
		// A passkey session would outlive the rule by up to 30 days otherwise.
		ended, err := q.DeleteNonSSOSessions(ctx)
		if err != nil {
			return err
		}
		audit.Set(ctx, "sessions_ended", ended)
		// The ones that stay get what a new session gets from now on.
		_, err = q.CapSessions(ctx, time.Now().Add(iam.SSOSessionTTL))
		return err
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.SetEnforceSSOResponse{Workspace: workspace.ToProto()}, nil
}

func (s *workspaceService) UpdateDaemonDefaults(
	ctx context.Context,
	req *nokkuv1.UpdateDaemonDefaultsRequest,
) (*nokkuv1.UpdateDaemonDefaultsResponse, error) {
	var workspace *db.Workspace
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		// Locked, so two tabs saving different settings at once keep both.
		base, err := q.GetWorkspaceForUpdate(ctx)
		if err != nil {
			return err
		}
		base.Settings = cmp.Or(base.Settings, &nokkuv1.WorkspaceSettings{})
		mergeSet(base.Settings.ProtoReflect(), (&nokkuv1.WorkspaceSettings{
			DefaultDaemonConfig: req.GetDefaultDaemonConfig(),
			SessionIdleTimeout:  req.GetSessionIdleTimeout(),
		}).ProtoReflect())
		workspace, err = q.UpdateWorkspace(ctx, &db.UpdateWorkspaceParams{Settings: base.Settings})
		return err
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.UpdateDaemonDefaultsResponse{Workspace: workspace.ToProto()}, nil
}

func (s *workspaceService) SetDefaultSafeguards(
	ctx context.Context,
	req *nokkuv1.SetDefaultSafeguardsRequest,
) (*nokkuv1.SetDefaultSafeguardsResponse, error) {
	var workspace *db.Workspace
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		base, err := q.GetWorkspaceForUpdate(ctx)
		if err != nil {
			return err
		}
		base.Settings = cmp.Or(base.Settings, &nokkuv1.WorkspaceSettings{})
		base.Settings.DefaultDaemonConfig = cmp.Or(base.Settings.GetDefaultDaemonConfig(), &nokkuv1.DaemonConfig{})
		setSafeguards(ctx, base.Settings.GetDefaultDaemonConfig(), &nokkuv1.SetDaemonSafeguardsRequest{
			RecordSessions: req.RecordSessions, KillOnRevoke: req.KillOnRevoke,
		})
		workspace, err = q.UpdateWorkspace(ctx, &db.UpdateWorkspaceParams{Settings: base.Settings})
		return err
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.SetDefaultSafeguardsResponse{Workspace: workspace.ToProto()}, nil
}

// DeleteWorkspace is hosted only, a self-hosted server serves nothing else.
func (s *workspaceService) DeleteWorkspace(
	ctx context.Context,
	_ *nokkuv1.DeleteWorkspaceRequest,
) (*nokkuv1.DeleteWorkspaceResponse, error) {
	if !s.cfg.SaaS {
		return nil, errSingleWorkspace
	}
	ws, _ := actor.WorkspaceFromContext(ctx)
	if err := deleteWorkspace(ctx, s.cfg, ws); err != nil {
		return nil, err
	}
	return &nokkuv1.DeleteWorkspaceResponse{}, nil
}

// FindWorkspaces mails an address the workspaces it can sign in to. It answers
// the same whether there are any, so it names no account and no customer.
func (s *workspaceService) FindWorkspaces(
	ctx context.Context,
	req *nokkuv1.FindWorkspacesRequest,
) (*nokkuv1.FindWorkspacesResponse, error) {
	if !s.cfg.SaaS || actor.WorkspaceIDFromContext(ctx) != "" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, "workspaces are only found on the root host")
	}
	addr := iam.NormalizeEmail(req.GetEmail())
	// Detached, so timing never shows if the address has an account.
	mailCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), findMailTimeout)
	go func() {
		defer cancel()
		if err := s.mailWorkspaces(mailCtx, addr); err != nil && !errors.Is(err, email.ErrCooldown) {
			slog.Warn("workspaces mail not sent", "error", err)
		}
	}()
	return &nokkuv1.FindWorkspacesResponse{}, nil
}

func (s *workspaceService) mailWorkspaces(ctx context.Context, addr string) error {
	rows, err := s.cfg.Conn.Sys().ListWorkspacesByEmail(ctx, addr)
	if err != nil || len(rows) == 0 {
		return err
	}
	list := make([]email.WorkspaceLink, len(rows))
	for i, row := range rows {
		list[i] = email.WorkspaceLink{Name: row.Name, URL: s.cfg.Tenant.BaseURL(row.Slug)}
	}
	return s.cfg.Email.SendWorkspacesEmail(ctx, addr, list)
}

// A deleted workspace's recording objects go through the delete queue.
func deleteWorkspace(ctx context.Context, cfg *app.Config, ws actor.Workspace) error {
	ctx = actor.WithWorkspace(ctx, ws)
	if err := cfg.Conn.Tenant().DeleteWorkspace(ctx, ws.ID); err != nil {
		return err
	}
	cfg.Tenant.Forget(ws.Slug)
	return nil
}

// CreateWorkspace is the hosted signup, undone if the sign-in link goes unused.
func (s *workspaceService) CreateWorkspace(
	ctx context.Context,
	req *nokkuv1.CreateWorkspaceRequest,
) (*nokkuv1.CreateWorkspaceResponse, error) {
	if !s.cfg.SaaS || actor.WorkspaceIDFromContext(ctx) != "" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, "signup only happens on the root host")
	}
	if tenant.Forbidden(req.GetSlug()) {
		return nil, connect.NewError(connect.CodeInvalidArgument, "this name is not available")
	}
	// Checked first, a workspace whose owner gets no mail sits until the purge.
	addr := iam.NormalizeEmail(req.GetOwnerEmail())
	if s.cfg.Email.OwnerLinkOnCooldown(addr) {
		return nil, connect.NewError(
			connect.CodeResourceExhausted,
			"a sign-in link went to this address a moment ago, try again later",
		)
	}
	if err := email.Verify(ctx, addr, true); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, "please enter a valid email address")
	}
	ws, err := tenant.Create(ctx, s.cfg.Conn, s.cfg.Keyset, req.GetSlug(), strings.TrimSpace(req.GetName()),
		entitlement.TrialDays)
	if db.IsUniqueViolation(err) {
		return nil, connect.NewError(connect.CodeAlreadyExists, "this name is taken")
	}
	if err != nil {
		return nil, err
	}
	// A request racing the purge may have cached the slug's last owner.
	s.cfg.Tenant.Forget(ws.Slug)

	wsCtx := actor.WithWorkspace(ctx, actor.Workspace{
		ID: ws.ID, Slug: ws.Slug, BaseURL: s.cfg.Tenant.BaseURL(ws.Slug),
	})
	owner, err := s.cfg.IAM.CreateOwner(wsCtx, addr, req.GetOwnerName())
	if err != nil {
		return nil, err
	}
	link, err := s.cfg.IAM.IssueBootstrapLink(wsCtx, owner)
	if err != nil {
		return nil, err
	}
	if err := s.cfg.Email.SendOwnerLinkEmail(ctx, addr, link, iam.BootstrapTTL); err != nil {
		slog.Error("signup mail not sent", "error", err, "workspace_id", ws.ID)
		return nil, errMailNotSent
	}
	// The call is public, so the audit interceptor has no actor for it.
	s.cfg.Audit.Record(wsCtx, &audit.Event{
		Action:    "CreateWorkspace",
		ActorID:   owner.ID,
		ActorKind: string(actor.KindUser),
		ActorName: addr,
		Target:    ws.ID,
		OK:        true,
	})
	return &nokkuv1.CreateWorkspaceResponse{Url: new(s.cfg.Tenant.BaseURL(ws.Slug))}, nil
}
