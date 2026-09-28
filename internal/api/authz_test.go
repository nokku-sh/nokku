package api

import (
	"errors"
	"fmt"
	"testing"

	"github.com/nokku-sh/nokku/internal/config"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokku/internal/iam"
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
		if got := ProcedureRoles[test.procedure]; got != test.want {
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

// Every procedure must sit in exactly one class, or the interceptor denies it.
func TestEveryProcedureIsClassified(t *testing.T) {
	for _, procedure := range allProcedures(t) {
		classes := 0
		if _, ok := ProcedureRoles[procedure]; ok {
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

func TestAuthorizePersonalAuditLog(t *testing.T) {
	a := &AuthorizationInterceptor{cfg: &config.Config{}}
	ctx := iam.ContextWithPrincipal(t.Context(), iam.Principal{ID: "u1", Kind: iam.KindUser})
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
