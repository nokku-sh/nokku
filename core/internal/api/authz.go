package api

import (
	"context"
	"errors"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// procedureAccess holds the (access) option of every RPC. RPCs without one are denied.
var procedureAccess = loadProcedureAccess()

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

// authorizationInterceptor checks the role the session carries, so no lookup happens here.
type authorizationInterceptor struct {
	cfg *config.Config
}

// A unary call is checked once its request is decoded, so the audit row of a denied call still names the target.
// Generated handlers receive before they run, a stream is checked up front.
func (a *authorizationInterceptor) intercept(next connect.ServerFunc) connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
		if spec.StreamType == connect.StreamTypeUnary {
			return next(ctx, spec, &authorizedStream{ServerStream: stream, ctx: ctx, procedure: spec.Procedure, a: a})
		}
		if err := a.authorize(ctx, spec.Procedure); err != nil {
			return err
		}
		return next(ctx, spec, stream)
	}
}

type authorizedStream struct {
	connect.ServerStream

	ctx       context.Context
	procedure string
	a         *authorizationInterceptor
}

func (s *authorizedStream) Receive(msg any) error {
	if err := s.ServerStream.Receive(msg); err != nil {
		return err
	}
	return s.a.authorize(s.ctx, s.procedure)
}

func (a *authorizationInterceptor) authorize(ctx context.Context, procedure string) error {
	access := procedureAccess[procedure]
	if access == nil {
		return db.ErrPermissionDenied
	}
	if access.GetPublic() {
		return nil
	}
	caller, _ := actor.PrincipalFromContext(ctx)
	if caller.Kind == actor.KindDaemon {
		if !access.GetDaemon() {
			return db.ErrPermissionDenied
		}
		return a.daemonAccepted(ctx, caller.ID, procedure)
	}
	if access.GetPeopleOnly() && caller.Kind == actor.KindServiceAccount {
		return db.ErrPermissionDenied
	}
	if access.GetSelf() {
		return nil
	}
	// An RPC that names no role stays denied.
	required := access.GetRole()
	if required == nokkuv1.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED || caller.Role < required {
		return db.ErrPermissionDenied
	}
	return nil
}

// daemonAccepted keeps a daemon that is not accepted away from every RPC but its status and removing itself.
func (a *authorizationInterceptor) daemonAccepted(ctx context.Context, daemonID, procedure string) error {
	switch procedure {
	case nokkuv1connect.DaemonControlServiceSyncDaemonProcedure,
		nokkuv1connect.DaemonControlServiceConnectProcedure,
		nokkuv1connect.DaemonControlServiceUnenrollDaemonProcedure:
		return nil
	}
	daemon, err := a.cfg.Conn.Tenant().GetDaemon(ctx, daemonID)
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

func callerRole(ctx context.Context) nokkuv1.WorkspaceRole {
	p, _ := actor.PrincipalFromContext(ctx)
	return p.Role
}
