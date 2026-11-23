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
	"github.com/nokku-sh/nokku/core/internal/app"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
)

// procedureAccess holds each RPC's (access) option. Without one it is denied.
var (
	procedureAccess = loadProcedureAccess()
	unaryProcedures = loadUnaryProcedures()
)

// authorizationInterceptor applies the (access) option in this order: daemon,
// nk, role or self, people only, browser, fresh sign-in, plan feature, signing, cap.
type authorizationInterceptor struct {
	cfg *app.Config
}

type authorizedStream struct {
	connect.ServerStream

	ctx       context.Context
	procedure string
	a         *authorizationInterceptor
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

// loadUnaryProcedures lists the calls that take one message and answer with one.
func loadUnaryProcedures() map[string]bool {
	out := make(map[string]bool)
	protoregistry.GlobalFiles.RangeFilesByPackage("nokku.v1", func(fd protoreflect.FileDescriptor) bool {
		for i := range fd.Services().Len() {
			svc := fd.Services().Get(i)
			for j := range svc.Methods().Len() {
				if m := svc.Methods().Get(j); !m.IsStreamingClient() && !m.IsStreamingServer() {
					out["/"+string(svc.FullName())+"/"+string(m.Name())] = true
				}
			}
		}
		return true
	})
	return out
}

func authorize(cfg *app.Config) connect.ServerInterceptor {
	return (&authorizationInterceptor{cfg: cfg}).intercept
}

// A unary call is checked once decoded, so plan gates can read it and a denied
// call's audit row names the target. Generated handlers receive before they
// run. A stream is checked up front.
func (a *authorizationInterceptor) intercept(next connect.ServerFunc) connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
		if spec.StreamType == connect.StreamTypeUnary {
			return next(ctx, spec, &authorizedStream{ServerStream: stream, ctx: ctx, procedure: spec.Procedure, a: a})
		}
		if err := a.authorize(ctx, spec.Procedure, nil); err != nil {
			return err
		}
		return next(ctx, spec, stream)
	}
}

func (s *authorizedStream) Receive(msg any) error {
	if err := s.ServerStream.Receive(msg); err != nil {
		return err
	}
	return s.a.authorize(s.ctx, s.procedure, msg)
}

// msg is a unary call's request. A stream passes nil and skips the plan gates.
func (a *authorizationInterceptor) authorize(ctx context.Context, procedure string, msg any) error {
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
	// nk gets what nk needs, so a phished or infected nk session can't run the workspace.
	if caller.Kind == actor.KindCLI && !access.GetNk() {
		return connect.NewError(connect.CodePermissionDenied, "do this in the web app")
	}
	// An RPC that names no role stays denied.
	required := access.GetRole()
	if !access.GetSelf() && (required == nokkuv1.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED || caller.Role < required) {
		return db.ErrPermissionDenied
	}
	// A leaked key reaches only what names machines.
	if caller.Kind == actor.KindServiceAccount && !access.GetMachine() {
		return connect.NewError(connect.CodePermissionDenied, "only people can do this, not a service account")
	}
	browser := access.GetBrowser()
	if caller.Kind == actor.KindUser && browser == nokkuv1.Browser_BROWSER_REFUSED {
		return connect.NewError(connect.CodePermissionDenied, "do this with nk")
	}
	// nk and a service account are in by the two checks above. The handler holds them to what they added.
	machineOrNk := caller.Kind == actor.KindCLI || caller.Kind == actor.KindServiceAccount
	if browser == nokkuv1.Browser_BROWSER_FRESH && !machineOrNk {
		if err := a.fresh(ctx, caller); err != nil {
			return err
		}
	}
	if msg == nil {
		return nil
	}
	// A plan gate must not read a field the mask leaves out.
	if req, ok := msg.(maskedRequest); ok {
		if _, err := applyMask(req, req.GetUpdateMask()); err != nil {
			return err
		}
	}
	ent := a.cfg.Entitlements
	features := entitlement.RequestedFeatures(msg)
	if f := access.GetFeature(); f != "" {
		features = append(features, f)
	}
	if err := ent.CheckFeatures(ctx, features); err != nil {
		return err
	}
	if access.GetSigns() {
		if err := ent.CheckSigning(ctx); err != nil {
			return err
		}
	}
	if ws := actor.WorkspaceIDFromContext(ctx); access.GetCapped() && ws != "" {
		return ent.CheckResources(ctx, ws)
	}
	return nil
}

// fresh lets only a person's browser session from the last 10 minutes through.
func (a *authorizationInterceptor) fresh(ctx context.Context, caller actor.Principal) error {
	switch caller.Kind {
	case actor.KindUser:
		if err := a.cfg.IAM.RequireRecentSignIn(ctx); err != nil {
			if ci, ok := connect.CallInfoForServerContext(ctx); ok {
				setCookie(ci, a.cfg.IAM.ClearSessionCookie())
			}
			return connect.NewError(connect.CodeUnauthenticated, "sign in again to continue")
		}
		return nil
	case actor.KindServiceAccount:
		return connect.NewError(connect.CodePermissionDenied, "only people can do this, not a service account")
	case actor.KindCLI, actor.KindDaemon, actor.KindSCIM:
	}
	return connect.NewError(connect.CodePermissionDenied, "do this in the web app")
}

// A daemon that is not accepted gets only its status and removing itself.
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
	if daemon.Daemon.Status != nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED {
		return db.ErrPermissionDenied
	}
	return nil
}

func callerRole(ctx context.Context) nokkuv1.WorkspaceRole {
	p, _ := actor.PrincipalFromContext(ctx)
	return p.Role
}

// callerID is what a created_by or granted_by column stores, nil without a principal.
func callerID(ctx context.Context) *string {
	if id := actor.SubjectFromContext(ctx); id != "" {
		return &id
	}
	return nil
}
