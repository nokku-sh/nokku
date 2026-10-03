package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
)

// procedureAccess holds the (access) option of every RPC, see access.proto
// in the protos repo. RPCs without one are denied.
var procedureAccess = loadProcedureAccess()

//nolint:exhaustive // UNSPECIFIED stays unmapped so an RPC without a role is denied
var workspaceRoles = map[nokkuv1.WorkspaceRole]db.Role{
	nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER: db.RoleMember,
	nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER: db.RoleViewer,
	nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR: db.RoleEditor,
	nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN:  db.RoleAdmin,
	nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER:  db.RoleOwner,
}

func loadProcedureAccess() map[string]*nokkuv1.Access {
	out := make(map[string]*nokkuv1.Access)
	protoregistry.GlobalFiles.RangeFilesByPackage("nokku.v1", func(fd protoreflect.FileDescriptor) bool {
		for i := range fd.Services().Len() {
			svc := fd.Services().Get(i)
			for j := range svc.Methods().Len() {
				m := svc.Methods().Get(j)
				if a, ok := proto.GetExtension(m.Options(), nokkuv1.E_Access).(*nokkuv1.Access); ok && a != nil {
					out["/"+string(svc.FullName())+"/"+string(m.Name())] = a
				}
			}
		}
		return true
	})
	return out
}

func isPublicEndpoint(procedure string) bool {
	return procedureAccess[procedure].GetPublic()
}

type authorizationInterceptor struct {
	cfg *config.Config
}

func newAuthZInterceptor(
	cfg *config.Config,
) *authorizationInterceptor {
	return &authorizationInterceptor{cfg: cfg}
}

func (a *authorizationInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		ctx, err := a.authorize(ctx, req.Spec().Procedure)
		if err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
}

func (a *authorizationInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return next
}

func (a *authorizationInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		ctx, err := a.authorize(ctx, conn.Spec().Procedure)
		if err != nil {
			return err
		}
		return next(ctx, conn)
	}
}

func (a *authorizationInterceptor) authorize(
	ctx context.Context,
	procedure string,
) (context.Context, error) {
	access := procedureAccess[procedure]
	if access == nil {
		return ctx, db.ErrPermissionDenied
	}
	caller, _ := actor.PrincipalFromContext(ctx)
	if caller.Kind == actor.KindDaemon {
		if !access.GetDaemon() {
			return ctx, db.ErrPermissionDenied
		}
		return ctx, a.daemonAccepted(ctx, caller.ID, procedure)
	}
	if access.GetPublic() || access.GetSelf() {
		return ctx, nil
	}
	role, ok := workspaceRoles[access.GetRole()]
	if !ok {
		return ctx, db.ErrPermissionDenied
	}
	if access.GetPersonal() && actor.WorkspaceIDFromContext(ctx) == "" {
		return ctx, nil
	}
	return actorHasRole(ctx, a.cfg.Conn, role)
}

// daemonAccepted keeps a pending, rejected or deleted daemon away from every
// RPC but the ones that tell it its status, and removing itself.
func (a *authorizationInterceptor) daemonAccepted(ctx context.Context, daemonID, procedure string) error {
	switch procedure {
	case nokkuv1connect.DaemonServiceSyncDaemonProcedure,
		nokkuv1connect.DaemonControlServiceConnectProcedure,
		nokkuv1connect.DaemonServiceDeleteDaemonProcedure:
		return nil
	}
	daemon, err := a.cfg.Conn.Sys().GetDaemon(ctx, daemonID)
	if errors.Is(err, pgx.ErrNoRows) {
		return db.ErrPermissionDenied
	}
	if err != nil {
		return err
	}
	if daemon.Status != nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED {
		return db.ErrPermissionDenied
	}
	return nil
}

// actorHasRole records the verified membership on the returned context so
// WithWorkspace and handlers skip another lookup.
func actorHasRole(
	ctx context.Context,
	conn *db.Connection,
	required db.Role,
) (context.Context, error) {
	caller, _ := actor.PrincipalFromContext(ctx)
	if caller.ID == "" {
		return ctx, db.ErrNoActor
	}
	workspaceID := actor.WorkspaceIDFromContext(ctx)
	if workspaceID == "" {
		return ctx, db.ErrWorkspaceNotPinned
	}
	role, err := conn.Sys().GetActorRole(ctx, &db.GetActorRoleParams{
		WorkspaceID: workspaceID,
		ActorID:     caller.ID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ctx, db.ErrWorkspaceNotAccessible
	}
	if err != nil {
		return ctx, err
	}
	if !db.Role(role).AtLeast(required) {
		return ctx, db.ErrPermissionDenied
	}
	return actor.WithMember(ctx, workspaceID, role), nil
}

func callerRole(ctx context.Context) db.Role {
	return db.Role(actor.MemberRole(ctx))
}
