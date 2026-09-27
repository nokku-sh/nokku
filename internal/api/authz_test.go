package api

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokku/internal/iam"
)

func TestProcedurePermissions(t *testing.T) {
	tests := []struct {
		procedure string
		want      db.Permission
	}{
		{nokkuv1connect.TargetServiceGetTargetProcedure, db.PermTargetsView},
		{nokkuv1connect.TargetServiceListTargetsProcedure, db.PermTargetsView},
		{nokkuv1connect.TargetServiceCreateTargetProcedure, db.PermTargetsEdit},
		{nokkuv1connect.TargetServiceDeleteTargetProcedure, db.PermTargetsEdit},

		{nokkuv1connect.TeamServiceGetTeamProcedure, db.PermTeamsView},
		{nokkuv1connect.TeamServiceAddTeamMemberProcedure, db.PermTeamsEdit},

		{nokkuv1connect.CertificateServiceGetCertificateAuthorityProcedure, db.PermCasView},
		{nokkuv1connect.CertificateServiceDeleteCertificateAuthorityProcedure, db.PermCasEdit},

		{nokkuv1connect.WorkspaceServiceUpdateWorkspaceProcedure, db.PermWorkspaceEdit},
		{nokkuv1connect.WorkspaceServiceDeleteWorkspaceProcedure, db.PermWorkspaceDelete},
		{nokkuv1connect.WorkspaceServiceListWorkspaceMembersProcedure, db.PermMembersView},
		{nokkuv1connect.WorkspaceServiceUpdateWorkspaceMemberProcedure, db.PermMembersEdit},

		{nokkuv1connect.PrincipalServiceListPrincipalsProcedure, db.PermPrincipalsView},
		{nokkuv1connect.PrincipalServiceRevokeAllAccessProcedure, db.PermPrincipalsEdit},

		{
			nokkuv1connect.ServiceAccountServiceGetServiceAccountProcedure,
			db.PermServiceAccountsView,
		},
		{
			nokkuv1connect.ServiceAccountServiceCreateServiceAccountProcedure,
			db.PermServiceAccountsEdit,
		},

		{nokkuv1connect.DaemonServiceGetDaemonProcedure, db.PermDaemonsView},
		{nokkuv1connect.DaemonServiceDeleteDaemonProcedure, db.PermDaemonsEdit},
		{nokkuv1connect.TokenServiceCreateTokenProcedure, db.PermSettingsEdit},

		{nokkuv1connect.SSOServiceGetSSOProviderProcedure, db.PermSsoView},
		{nokkuv1connect.SSOServiceUpdateSSOProviderProcedure, db.PermSsoEdit},

		{nokkuv1connect.WorkspaceDomainServiceGetWorkspaceDomainProcedure, db.PermDomainsView},
		{nokkuv1connect.WorkspaceDomainServiceVerifyWorkspaceDomainProcedure, db.PermDomainsEdit},

		{nokkuv1connect.BillingServiceGetBillingProcedure, db.PermSettingsView},
		{nokkuv1connect.TokenServiceDeleteTokenProcedure, db.PermSettingsEdit},
	}

	for _, test := range tests {
		t.Run(test.procedure, func(t *testing.T) {
			if got := ProcedurePermissions[test.procedure]; got != test.want {
				t.Fatalf("permission = %q, want %q", got, test.want)
			}
		})
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

// Every procedure must sit in exactly one class, or the interceptor denies it.
func TestEveryProcedureIsClassified(t *testing.T) {
	for _, procedure := range allProcedures(t) {
		classes := 0
		if _, ok := ProcedurePermissions[procedure]; ok {
			classes++
		}
		if _, ok := selfScopedProcedures[procedure]; ok {
			classes++
		}
		if _, ok := daemonOnlyProcedures[procedure]; ok {
			classes++
		}
		if isPublicEndpoint(procedure) {
			classes++
		}
		if classes != 1 {
			t.Errorf("%s is in %d authorization classes, want exactly 1", procedure, classes)
		}
	}
}

func TestAuthorizeDaemon(t *testing.T) {
	a := &AuthorizationInterceptor{}
	ctx := iam.ContextWithPrincipal(t.Context(), iam.Principal{ID: "d1", Kind: iam.KindDaemon})

	for _, procedure := range allProcedures(t) {
		_, only := daemonOnlyProcedures[procedure]
		_, shared := daemonSharedProcedures[procedure]
		_, err := a.authorize(ctx, procedure)
		if only || shared {
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
	a := &AuthorizationInterceptor{}
	ctx := iam.ContextWithPrincipal(t.Context(), iam.Principal{ID: "u1", Kind: iam.KindUser})
	for procedure := range daemonOnlyProcedures {
		if _, err := a.authorize(ctx, procedure); !errors.Is(err, db.ErrPermissionDenied) {
			t.Errorf("user allowed %s, want permission denied", procedure)
		}
	}
}

func TestAuthorizeUnknownProcedure(t *testing.T) {
	a := &AuthorizationInterceptor{}
	ctx := iam.ContextWithPrincipal(t.Context(), iam.Principal{ID: "u1", Kind: iam.KindUser})
	if _, err := a.authorize(ctx, "/nokku.v1.UnknownService/Unknown"); !errors.Is(err, db.ErrPermissionDenied) {
		t.Fatalf("unknown procedure: err = %v, want permission denied", err)
	}
}
