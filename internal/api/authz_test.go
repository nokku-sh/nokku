package api

import (
	"errors"
	"fmt"
	"testing"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/config"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/db"
)

func TestProcedureRoles(t *testing.T) {
	tests := []struct {
		procedure string
		want      db.Role
	}{
		{nokkuv1connect.CertificateServiceListCertificateAuthoritiesProcedure, db.RoleMember},
		{nokkuv1connect.DaemonServiceCreateSessionProcedure, db.RoleMember},

		{nokkuv1connect.TargetServiceListTargetsProcedure, db.RoleViewer},
		{nokkuv1connect.WorkspaceServiceListWorkspaceMembersProcedure, db.RoleViewer},
		{nokkuv1connect.UtilServiceListAuditLogsProcedure, db.RoleViewer},

		{nokkuv1connect.TargetServiceDeleteTargetProcedure, db.RoleEditor},
		{nokkuv1connect.PrincipalServiceRevokeAllAccessProcedure, db.RoleEditor},
		{nokkuv1connect.ServiceAccountServiceCreateServiceAccountProcedure, db.RoleEditor},

		{nokkuv1connect.WorkspaceServiceUpdateWorkspaceMemberProcedure, db.RoleAdmin},
		{nokkuv1connect.TokenServiceCreateTokenProcedure, db.RoleAdmin},
		{nokkuv1connect.SSOServiceUpdateSSOProviderProcedure, db.RoleAdmin},
		{nokkuv1connect.BillingServiceGetBillingProcedure, db.RoleAdmin},

		{nokkuv1connect.WorkspaceServiceDeleteWorkspaceProcedure, db.RoleOwner},
	}

	for _, test := range tests {
		if got := workspaceRoles[procedureAccess[test.procedure].GetRole()]; got != test.want {
			t.Errorf("%s role = %q, want %q", test.procedure, got, test.want)
		}
	}
}

// allProcedures lists every RPC of the nokku.v1 package from the generated
// descriptors, so a new RPC shows up here without anyone listing it.
func allProcedures(t *testing.T) []string {
	t.Helper()
	_ = nokkuv1.File_nokku_v1_daemon_proto
	var out []string
	protoregistry.GlobalFiles.RangeFilesByPackage("nokku.v1", func(fd protoreflect.FileDescriptor) bool {
		for i := range fd.Services().Len() {
			svc := fd.Services().Get(i)
			for j := range svc.Methods().Len() {
				out = append(out, fmt.Sprintf("/%s/%s", svc.FullName(), svc.Methods().Get(j).Name()))
			}
		}
		return true
	})
	if len(out) == 0 {
		t.Fatal("no nokku.v1 procedures registered")
	}
	return out
}

// daemonOnly is an access with nothing but daemon set.
func daemonOnly(a *nokkuv1.Access) bool {
	return a.GetDaemon() && !a.GetPublic() && !a.GetSelf() &&
		a.GetRole() == nokkuv1.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED
}

// Every procedure must sit in exactly one class, or the interceptor denies it.
func TestEveryProcedureIsClassified(t *testing.T) {
	for _, procedure := range allProcedures(t) {
		access := procedureAccess[procedure]
		if access == nil {
			t.Errorf("%s has no (access) option", procedure)
			continue
		}
		classes := 0
		if access.GetPublic() {
			classes++
		}
		if access.GetSelf() {
			classes++
		}
		if access.GetRole() != nokkuv1.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED {
			if _, ok := workspaceRoles[access.GetRole()]; !ok {
				t.Errorf("%s has unmapped role %s", procedure, access.GetRole())
			}
			classes++
		}
		if daemonOnly(access) {
			classes++
		}
		if classes != 1 {
			t.Errorf("%s is in %d authorization classes, want exactly 1", procedure, classes)
		}
		if access.GetPersonal() && access.GetRole() == nokkuv1.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED {
			t.Errorf("%s is personal without a role", procedure)
		}
	}
}

func TestAuthorizeDaemon(t *testing.T) {
	a := &authorizationInterceptor{}
	ctx := actor.ContextWithPrincipal(t.Context(), actor.Principal{ID: "d1", Kind: actor.KindDaemon})

	for _, procedure := range allProcedures(t) {
		_, err := a.authorize(ctx, procedure)
		if procedureAccess[procedure].GetDaemon() {
			if err != nil {
				t.Errorf("daemon denied %s: %v", procedure, err)
			}
			continue
		}
		if !errors.Is(err, db.ErrPermissionDenied) {
			t.Errorf("daemon allowed %s, want permission denied", procedure)
		}
	}
}

func TestAuthorizeUserOnDaemonProcedures(t *testing.T) {
	a := &authorizationInterceptor{}
	ctx := actor.ContextWithPrincipal(t.Context(), actor.Principal{ID: "u1", Kind: actor.KindUser})
	for procedure, access := range procedureAccess {
		if !daemonOnly(access) {
			continue
		}
		if _, err := a.authorize(ctx, procedure); !errors.Is(err, db.ErrPermissionDenied) {
			t.Errorf("user allowed %s, want permission denied", procedure)
		}
	}
}

func TestAuthorizeUserStreamWithoutWorkspace(t *testing.T) {
	a := &authorizationInterceptor{}
	ctx := actor.ContextWithPrincipal(t.Context(), actor.Principal{ID: "u1", Kind: actor.KindUser})
	for _, procedure := range []string{
		nokkuv1connect.RecordingServiceGetRecordingProcedure,
		nokkuv1connect.DaemonServiceRelayProcedure,
	} {
		if _, err := a.authorize(ctx, procedure); err != nil {
			t.Errorf("user denied %s before the handler pins a workspace: %v", procedure, err)
		}
	}
}

func TestAuthorizeUnknownProcedure(t *testing.T) {
	a := &authorizationInterceptor{}
	ctx := actor.ContextWithPrincipal(t.Context(), actor.Principal{ID: "u1", Kind: actor.KindUser})
	if _, err := a.authorize(ctx, "/nokku.v1.UnknownService/Unknown"); !errors.Is(err, db.ErrPermissionDenied) {
		t.Fatalf("unknown procedure: err = %v, want permission denied", err)
	}
}

func TestAuthorizePersonalAuditLog(t *testing.T) {
	a := &authorizationInterceptor{cfg: &config.Config{}}
	ctx := actor.ContextWithPrincipal(t.Context(), actor.Principal{ID: "u1", Kind: actor.KindUser})
	if _, err := a.authorize(ctx, nokkuv1connect.UtilServiceListAuditLogsProcedure); err != nil {
		t.Fatalf("personal audit log without a workspace: err = %v, want allowed", err)
	}
	if _, err := a.authorize(
		ctx,
		nokkuv1connect.TargetServiceListTargetsProcedure,
	); !errors.Is(
		err,
		db.ErrWorkspaceNotPinned,
	) {
		t.Fatalf("workspace procedure without a workspace: err = %v, want not pinned", err)
	}
}
