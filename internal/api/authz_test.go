package api

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/db"
)

func TestProcedureRoles(t *testing.T) {
	tests := []struct {
		procedure string
		want      nokkuv1.WorkspaceRole
	}{
		{
			nokkuv1connect.CertificateServiceListCertificateAuthoritiesProcedure,
			nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
		},
		{nokkuv1connect.DaemonServiceCreateSessionProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER},
		{nokkuv1connect.DaemonServiceRelayProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER},

		{nokkuv1connect.TargetServiceListTargetsProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER},
		{nokkuv1connect.WorkspaceServiceListUsersProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER},
		{nokkuv1connect.UtilServiceListAuditLogsProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER},
		{nokkuv1connect.RecordingServiceGetRecordingProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER},

		{nokkuv1connect.TargetServiceDeleteTargetProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR},
		{nokkuv1connect.TargetAccountServiceRevokeAllAccessProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR},
		{
			nokkuv1connect.ServiceAccountServiceCreateServiceAccountProcedure,
			nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR,
		},

		{nokkuv1connect.WorkspaceServiceUpdateUserRoleProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN},
		{nokkuv1connect.WorkspaceServiceSetUserActiveProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN},
		{nokkuv1connect.WorkspaceServiceDeleteUserProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN},
		{nokkuv1connect.TokenServiceCreateTokenProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN},
		{nokkuv1connect.BillingServiceGetBillingProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN},

		{nokkuv1connect.WorkspaceServiceUpdateWorkspaceProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER},
		{nokkuv1connect.WorkspaceServiceDeleteWorkspaceProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER},
		{nokkuv1connect.WorkspaceServiceTransferOwnershipProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER},
		{nokkuv1connect.BillingServiceActivateLicenseProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER},
		{nokkuv1connect.SSOServicePutSSOProviderProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER},
		{nokkuv1connect.SSOServiceDeleteSSOProviderProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER},
		{nokkuv1connect.SCIMServiceCreateSCIMTokenProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER},
		{nokkuv1connect.SCIMServiceDeleteSCIMTokenProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER},
	}

	for _, test := range tests {
		if got := procedureAccess[test.procedure].GetRole(); got != test.want {
			t.Errorf("%s role = %s, want %s", test.procedure, got, test.want)
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
			if _, ok := nokkuv1.WorkspaceRole_name[int32(access.GetRole())]; !ok {
				t.Errorf("%s has an undefined role %d", procedure, access.GetRole())
			}
			classes++
		}
		if daemonOnly(access) {
			classes++
		}
		if classes != 1 {
			t.Errorf("%s is in %d authorization classes, want exactly 1", procedure, classes)
		}
	}
}

// No request names a workspace. The host does, before authentication.
func TestRequestsCarryNoWorkspace(t *testing.T) {
	for _, procedure := range allProcedures(t) {
		name := protoreflect.FullName(strings.ReplaceAll(strings.TrimPrefix(procedure, "/"), "/", "."))
		desc, err := protoregistry.GlobalFiles.FindDescriptorByName(name)
		if err != nil {
			t.Errorf("%s: %v", procedure, err)
			continue
		}
		if desc.(protoreflect.MethodDescriptor).Input().Fields().ByName("workspace_id") != nil {
			t.Errorf("%s names a workspace in its request", procedure)
		}
	}
}

func TestAuthorizeDaemon(t *testing.T) {
	a := &authorizationInterceptor{}
	ctx := actor.ContextWithPrincipal(t.Context(), actor.Principal{ID: "d1", Kind: actor.KindDaemon})
	// These answer a daemon in any state. The rest look the daemon up, see
	// TestPendingDaemonIsDenied.
	anyState := []string{
		nokkuv1connect.DaemonControlServiceSyncDaemonProcedure,
		nokkuv1connect.DaemonControlServiceConnectProcedure,
		nokkuv1connect.DaemonControlServiceUnenrollDaemonProcedure,
	}

	for _, procedure := range allProcedures(t) {
		switch {
		case procedureAccess[procedure].GetPublic():
		case !procedureAccess[procedure].GetDaemon():
			if err := a.authorize(ctx, procedure); !errors.Is(err, db.ErrPermissionDenied) {
				t.Errorf("daemon allowed %s, want permission denied", procedure)
			}
		case slices.Contains(anyState, procedure):
			if err := a.authorize(ctx, procedure); err != nil {
				t.Errorf("daemon denied %s: %v", procedure, err)
			}
		}
	}
}

// A daemon's whole surface is one service, and nothing else lives there but
// the public enrollment.
func TestDaemonProceduresLiveInControlService(t *testing.T) {
	for procedure, access := range procedureAccess {
		inService := strings.HasPrefix(procedure, "/nokku.v1.DaemonControlService/")
		if procedure == nokkuv1connect.DaemonControlServiceEnrollDaemonProcedure {
			continue
		}
		if inService != daemonOnly(access) || inService != access.GetDaemon() {
			t.Errorf("%s: daemon procedures and DaemonControlService must be the same set", procedure)
		}
	}
}

func TestAuthorizeUserOnDaemonProcedures(t *testing.T) {
	a := &authorizationInterceptor{}
	ctx := actor.ContextWithPrincipal(
		t.Context(),
		actor.Principal{ID: "u1", Kind: actor.KindUser, Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER},
	)
	for procedure, access := range procedureAccess {
		if !daemonOnly(access) {
			continue
		}
		if err := a.authorize(ctx, procedure); !errors.Is(err, db.ErrPermissionDenied) {
			t.Errorf("user allowed %s, want permission denied", procedure)
		}
	}
}

// The role comes with the principal, so no lookup happens here.
func TestAuthorizeRoleFromPrincipal(t *testing.T) {
	a := &authorizationInterceptor{}
	as := func(role nokkuv1.WorkspaceRole) context.Context {
		return actor.ContextWithPrincipal(t.Context(), actor.Principal{ID: "u1", Kind: actor.KindUser, Role: role})
	}
	tests := []struct {
		role      nokkuv1.WorkspaceRole
		procedure string
		allowed   bool
	}{
		{nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER, nokkuv1connect.DaemonServiceRelayProcedure, true},
		{nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER, nokkuv1connect.RecordingServiceGetRecordingProcedure, false},
		{nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER, nokkuv1connect.RecordingServiceGetRecordingProcedure, true},
		{nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER, nokkuv1connect.TargetServiceDeleteTargetProcedure, false},
		{nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR, nokkuv1connect.TargetServiceDeleteTargetProcedure, true},
		{nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN, nokkuv1connect.SSOServicePutSSOProviderProcedure, false},
		{nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER, nokkuv1connect.SSOServicePutSSOProviderProcedure, true},
		{nokkuv1.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED, nokkuv1connect.TargetServiceListTargetsProcedure, false},
		{nokkuv1.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED, nokkuv1connect.AccountServiceGetAccountProcedure, true},
	}
	for _, tt := range tests {
		err := a.authorize(as(tt.role), tt.procedure)
		if (err == nil) != tt.allowed {
			t.Errorf("%s on %s: err = %v, want allowed=%v", tt.role, tt.procedure, err, tt.allowed)
		}
	}
}

func TestAuthorizeUnknownProcedure(t *testing.T) {
	a := &authorizationInterceptor{}
	ctx := actor.ContextWithPrincipal(
		t.Context(),
		actor.Principal{ID: "u1", Kind: actor.KindUser, Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER},
	)
	if err := a.authorize(ctx, "/nokku.v1.UnknownService/Unknown"); !errors.Is(err, db.ErrPermissionDenied) {
		t.Fatalf("unknown procedure: err = %v, want permission denied", err)
	}
}
