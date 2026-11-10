package api

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
)

func TestProcedureRoles(t *testing.T) {
	tests := []struct {
		procedure string
		want      nokkuv1.WorkspaceRole
	}{
		{
			nokkuv1connect.CertificateServiceGetCertificateAuthorityProcedure,
			nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
		},
		{nokkuv1connect.DaemonServiceCreateSessionProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER},
		{nokkuv1connect.DaemonServiceRelayProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER},

		{nokkuv1connect.TargetServiceListTargetsProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER},
		{nokkuv1connect.WorkspaceServiceListUsersProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER},
		{nokkuv1connect.UtilServiceListAuditLogsProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER},
		{nokkuv1connect.RecordingServiceGetRecordingProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER},
		{
			nokkuv1connect.ServiceAccountServiceListServiceAccountTokensProcedure,
			nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER,
		},

		{nokkuv1connect.TargetServiceDeleteTargetProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR},
		{nokkuv1connect.TargetAccountServiceRevokeAllAccessProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR},
		{
			nokkuv1connect.ServiceAccountServiceCreateServiceAccountProcedure,
			nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR,
		},
		{
			nokkuv1connect.ServiceAccountServiceCreateServiceAccountTokenProcedure,
			nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR,
		},
		{
			nokkuv1connect.ServiceAccountServiceRevokeServiceAccountTokenProcedure,
			nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR,
		},

		{nokkuv1connect.WorkspaceServiceUpdateUserRoleProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN},
		{nokkuv1connect.WorkspaceServiceSetUserActiveProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN},
		{nokkuv1connect.WorkspaceServiceDeleteUserProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN},
		{nokkuv1connect.JoinTokenServiceCreateJoinTokenProcedure, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN},
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
		assert.Equal(t, test.want, procedureAccess[test.procedure].GetRole(), test.procedure)
	}
}

// allProcedures reads the descriptors, so a new RPC shows up here by itself.
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
	require.NotEmpty(t, out, "no nokku.v1 procedures registered")
	return out
}

func daemonOnly(a *nokkuv1.Access) bool {
	return a.GetDaemon() && !a.GetPublic() && !a.GetSelf() &&
		a.GetRole() == nokkuv1.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED
}

// Every procedure must sit in exactly one class, or the interceptor denies it.
func TestEveryProcedureIsClassified(t *testing.T) {
	for _, procedure := range allProcedures(t) {
		access := procedureAccess[procedure]
		if !assert.NotNil(t, access, "%s has no (access) option", procedure) {
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
			assert.Contains(t, nokkuv1.WorkspaceRole_name, int32(access.GetRole()),
				"%s has an undefined role", procedure)
			classes++
		}
		if daemonOnly(access) {
			classes++
		}
		assert.Equal(t, 1, classes, "%s must be in exactly one authorization class", procedure)
		if access.GetPeopleOnly() {
			assert.NotEqual(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED, access.GetRole(),
				"%s is people_only without a role", procedure)
		}
	}
}

// No request names a workspace. The host does, before authentication.
func TestRequestsCarryNoWorkspace(t *testing.T) {
	for _, procedure := range allProcedures(t) {
		name := protoreflect.FullName(strings.ReplaceAll(strings.TrimPrefix(procedure, "/"), "/", "."))
		desc, err := protoregistry.GlobalFiles.FindDescriptorByName(name)
		if assert.NoError(t, err, procedure) {
			workspace := desc.(protoreflect.MethodDescriptor).Input().Fields().ByName("workspace_id")
			assert.Nil(t, workspace, "%s names a workspace in its request", procedure)
		}
	}
}

func TestAuthorizeDaemon(t *testing.T) {
	a := &authorizationInterceptor{}
	ctx := actor.ContextWithPrincipal(t.Context(), actor.Principal{ID: "d1", Kind: actor.KindDaemon})
	// Any daemon state passes these. The rest: TestPendingDaemonIsDenied.
	anyState := []string{
		nokkuv1connect.DaemonControlServiceSyncDaemonProcedure,
		nokkuv1connect.DaemonControlServiceConnectProcedure,
		nokkuv1connect.DaemonControlServiceUnenrollDaemonProcedure,
	}

	for _, procedure := range allProcedures(t) {
		access := procedureAccess[procedure]
		if access.GetPublic() {
			continue
		}
		if !access.GetDaemon() {
			assert.ErrorIs(t, a.authorize(ctx, procedure, nil), db.ErrPermissionDenied, "daemon allowed %s", procedure)
		} else if slices.Contains(anyState, procedure) {
			assert.NoError(t, a.authorize(ctx, procedure, nil), "daemon denied %s", procedure)
		}
	}
}

// A daemon's whole surface is one service, shared only with enrollment.
func TestDaemonProceduresLiveInControlService(t *testing.T) {
	for procedure, access := range procedureAccess {
		inService := strings.HasPrefix(procedure, "/nokku.v1.DaemonControlService/")
		if procedure == nokkuv1connect.DaemonControlServiceEnrollDaemonProcedure {
			continue
		}
		same := inService == daemonOnly(access) && inService == access.GetDaemon()
		assert.True(t, same, "%s: daemon procedures and DaemonControlService must be the same set", procedure)
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
		assert.ErrorIs(t, a.authorize(ctx, procedure, nil), db.ErrPermissionDenied, "user allowed %s", procedure)
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
		{nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER, nokkuv1connect.WorkspaceServiceUpdateWorkspaceProcedure, true},
		{nokkuv1.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED, nokkuv1connect.TargetServiceListTargetsProcedure, false},
		{nokkuv1.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED, nokkuv1connect.AccountServiceGetAccountProcedure, true},
	}
	for _, tt := range tests {
		err := a.authorize(as(tt.role), tt.procedure, nil)
		assert.Equal(t, tt.allowed, err == nil, "%s on %s: err = %v", tt.role, tt.procedure, err)
	}
}

// A service account token must not mint credentials that outlive revoking it.
func TestAuthorizePeopleOnly(t *testing.T) {
	a := &authorizationInterceptor{}
	// Even the top role, so only people_only can refuse.
	owner := nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER
	as := func(kind actor.Kind) context.Context {
		return actor.ContextWithPrincipal(t.Context(), actor.Principal{ID: "p1", Kind: kind, Role: owner})
	}
	tests := []struct {
		kind      actor.Kind
		procedure string
		allowed   bool
	}{
		{actor.KindServiceAccount, nokkuv1connect.ServiceAccountServiceCreateServiceAccountTokenProcedure, false},
		{actor.KindServiceAccount, nokkuv1connect.ServiceAccountServiceCreateServiceAccountProcedure, false},
		{actor.KindServiceAccount, nokkuv1connect.AccessRequestServiceCreateAccessRequestProcedure, false},
		{actor.KindServiceAccount, nokkuv1connect.AccessRequestServiceApproveAccessRequestProcedure, false},
		{actor.KindServiceAccount, nokkuv1connect.AccessRequestServiceDenyAccessRequestProcedure, false},
		{actor.KindServiceAccount, nokkuv1connect.AccessRequestServiceCancelAccessRequestProcedure, false},
		{actor.KindServiceAccount, nokkuv1connect.DaemonServiceCreateSessionProcedure, false},
		{actor.KindUser, nokkuv1connect.AccessRequestServiceApproveAccessRequestProcedure, true},
		{actor.KindServiceAccount, nokkuv1connect.ServiceAccountServiceListServiceAccountsProcedure, true},
		{actor.KindServiceAccount, nokkuv1connect.TargetServiceDeleteTargetProcedure, true},
		{actor.KindUser, nokkuv1connect.ServiceAccountServiceCreateServiceAccountProcedure, true},
		{actor.KindCLI, nokkuv1connect.AccessRequestServiceCreateAccessRequestProcedure, true},
	}
	for _, tt := range tests {
		err := a.authorize(as(tt.kind), tt.procedure, nil)
		assert.Equal(t, tt.allowed, err == nil, "%s on %s: err = %v", tt.kind, tt.procedure, err)
	}
}

// A machine key adds and removes servers through nk sync. Who has access is for people to change, so a new editor
// call is refused for machines until it is listed here.
func TestMachinesOnlyReachTheNkSyncCalls(t *testing.T) {
	a := &authorizationInterceptor{}
	editor := nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR
	machine := actor.ContextWithPrincipal(
		t.Context(),
		actor.Principal{ID: "sa1", Kind: actor.KindServiceAccount, Role: editor},
	)
	var reached []string
	for _, procedure := range allProcedures(t) {
		if procedureAccess[procedure].GetRole() == editor && a.authorize(machine, procedure, nil) == nil {
			reached = append(reached, procedure)
		}
	}
	assert.ElementsMatch(t, []string{
		nokkuv1connect.TargetServiceCreateTargetProcedure,
		nokkuv1connect.TargetServiceDeleteTargetProcedure,
		nokkuv1connect.TargetServiceSyncTargetUsersProcedure,
	}, reached)
}

func TestAuthorizeUnknownProcedure(t *testing.T) {
	a := &authorizationInterceptor{}
	ctx := actor.ContextWithPrincipal(
		t.Context(),
		actor.Principal{ID: "u1", Kind: actor.KindUser, Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER},
	)
	require.ErrorIs(t, a.authorize(ctx, "/nokku.v1.UnknownService/Unknown", nil), db.ErrPermissionDenied)
}

// nk gets the calls nk makes and nothing else, whatever the person's role, so a
// phished or infected nk session can't change roles, grants or recordings.
func TestAuthorizeCLIOnlyWhatNkNeeds(t *testing.T) {
	a := &authorizationInterceptor{}
	ctx := actor.ContextWithPrincipal(
		t.Context(),
		actor.Principal{ID: "u1", Kind: actor.KindCLI, Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER},
	)
	allowed := 0
	for _, procedure := range allProcedures(t) {
		access := procedureAccess[procedure]
		if access.GetPublic() || access.GetDaemon() {
			continue
		}
		err := a.authorize(ctx, procedure, nil)
		if access.GetCli() {
			allowed++
			assert.NoError(t, err, "nk needs %s", procedure)
			continue
		}
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "nk reached %s: %v", procedure, err)
	}
	require.NotZero(t, allowed, "no call is open to nk")
}

// Only a person adds a way in. A stolen nk state file or service account key
// would mint credentials for good. The owner role pins it beyond today's caps.
func TestAuthorizeFreshNeedsAPerson(t *testing.T) {
	a := &authorizationInterceptor{}
	for _, kind := range []actor.Kind{actor.KindCLI, actor.KindServiceAccount} {
		ctx := actor.ContextWithPrincipal(
			t.Context(),
			actor.Principal{ID: "p1", Kind: kind, Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER},
		)
		fresh := 0
		for _, procedure := range allProcedures(t) {
			if !procedureAccess[procedure].GetFresh() {
				continue
			}
			fresh++
			err := a.authorize(ctx, procedure, nil)
			assert.Equal(
				t,
				connect.CodePermissionDenied,
				connect.CodeOf(err),
				"%s on %s: err = %v",
				kind,
				procedure,
				err,
			)
		}
		require.NotZero(t, fresh, "no procedure asks for a fresh sign-in")
	}
}
