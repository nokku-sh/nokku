package api

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"

	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
)

// Gated by what a request asks for, kept by hand next to RequestedFeatures.
var conditionalFeatures = []string{
	entitlement.FeatureEnforceSSO, entitlement.FeatureExpiringAccess, entitlement.FeatureIdleTimeout,
	entitlement.FeatureAccessRequests, entitlement.FeatureAuditStreaming,
}

// uncappedCreates have their bound somewhere else, with the place named.
var uncappedCreates = map[string]string{
	"/nokku.v1.WorkspaceService/CreateWorkspace":                "pre-tenant, bounded by the auth rate limit",
	"/nokku.v1.DaemonService/CreateSession":                     "no lasting row, recording storage evicts",
	"/nokku.v1.AccessRequestService/CreateAccessRequest":        "handler: maxDailyRequests per person",
	"/nokku.v1.AuditStreamService/CreateAuditStream":            "handler: maxAuditStreams per workspace",
	"/nokku.v1.InvitationService/CreateInvitation":              "one row per address, gone in 7 days, the seat cap refuses it",
	"/nokku.v1.JoinTokenService/CreateJoinToken":                "a token, enrolling counts against the cap",
	"/nokku.v1.ServiceAccountService/CreateServiceAccountToken": "a token on a capped account",
	"/nokku.v1.SCIMService/CreateSCIMToken":                     "a token, SCIM users count against seats",
}

// Every rule of every call in one file, so a change shows up in review.
// UPDATE_GOLDEN=1 writes the file.
func TestRulesGolden(t *testing.T) {
	var lines []string
	for _, procedure := range allProcedures(t) {
		a := procedureAccess[procedure]
		name := protoreflect.FullName(strings.ReplaceAll(strings.TrimPrefix(procedure, "/"), "/", "."))
		md, err := protoregistry.GlobalFiles.FindDescriptorByName(name)
		require.NoError(t, err, procedure)
		lines = append(lines, fmt.Sprintf(
			"%s public=%t self=%t role=%s daemon=%t cli=%t people_only=%t fresh=%t feature=%s capped=%t signs=%t audited=%t",
			procedure,
			a.GetPublic(),
			a.GetSelf(),
			strings.TrimPrefix(a.GetRole().String(), "WORKSPACE_ROLE_"),
			a.GetDaemon(),
			a.GetCli(),
			a.GetPeopleOnly(),
			a.GetFresh(),
			a.GetFeature(),
			a.GetCapped(),
			a.GetSigns(),
			audit.Records(md),
		))
	}
	slices.Sort(lines)
	got := strings.Join(lines, "\n") + "\n"
	path := filepath.Join("testdata", "rules.golden")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.MkdirAll("testdata", 0o750))
		require.NoError(t, os.WriteFile(path, []byte(got), 0o600))
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err, "no golden file yet, run with UPDATE_GOLDEN=1")
	assert.Equal(t, string(want), got, "the rules changed, review the diff and rerun with UPDATE_GOLDEN=1")
}

// A paid feature no call enforces leaks revenue, a gate no plan has is dead.
func TestEveryFeatureIsGated(t *testing.T) {
	gated := slices.Clone(conditionalFeatures)
	for _, procedure := range allProcedures(t) {
		if f := procedureAccess[procedure].GetFeature(); f != "" {
			gated = append(gated, f)
		}
	}
	for _, f := range entitlement.CatalogFeatures {
		assert.Contains(t, gated, f.Code,
			"feature %q is gated nowhere: declare it on a call, or list it as free", f.Code)
	}
	for _, f := range gated {
		inCatalog := slices.ContainsFunc(entitlement.CatalogFeatures, func(c entitlement.Feature) bool {
			return c.Code == f
		})
		assert.True(t, inCatalog, "a call needs feature %q, which no plan has", f)
	}
}

// Handing out a credential takes a recent sign-in, or a stolen cookie lasts.
func TestEveryTokenCallIsFresh(t *testing.T) {
	for _, procedure := range allProcedures(t) {
		_, method, _ := strings.Cut(strings.TrimPrefix(procedure, "/"), "/")
		if strings.HasPrefix(method, "Create") && strings.HasSuffix(method, "Token") {
			assert.True(t, procedureAccess[procedure].GetFresh(), "%s hands out a credential, mark it fresh", procedure)
		}
	}
}

// A stolen session must not quietly change who signs in or where audit goes.
func TestSignInAndAuditChangesAreFresh(t *testing.T) {
	for _, procedure := range []string{
		nokkuv1connect.SSOServicePutSSOProviderProcedure,
		nokkuv1connect.SSOServiceDeleteSSOProviderProcedure,
		nokkuv1connect.AuditStreamServiceCreateAuditStreamProcedure,
		nokkuv1connect.AuditStreamServiceUpdateAuditStreamProcedure,
		nokkuv1connect.AuditStreamServiceDeleteAuditStreamProcedure,
		nokkuv1connect.WorkspaceServiceTransferOwnershipProcedure,
		nokkuv1connect.WorkspaceServiceDeleteWorkspaceProcedure,
		nokkuv1connect.WorkspaceServiceUpdateUserRoleProcedure,
		nokkuv1connect.RecordingServiceDeleteRecordingProcedure,
	} {
		assert.True(t, procedureAccess[procedure].GetFresh(), "%s needs a recent sign-in", procedure)
	}
}

func TestRequestedFresh(t *testing.T) {
	update := func(s *nokkuv1.WorkspaceSettings) *nokkuv1.UpdateWorkspaceRequest {
		return &nokkuv1.UpdateWorkspaceRequest{Name: new("renamed"), Settings: s}
	}
	assert.True(t, requestedFresh(update(&nokkuv1.WorkspaceSettings{EnforceSso: new(true)})), "turning SSO on")
	assert.True(t, requestedFresh(update(&nokkuv1.WorkspaceSettings{EnforceSso: new(false)})), "turning SSO off")
	assert.False(t, requestedFresh(update(nil)), "a rename stays free")
	assert.False(t, requestedFresh(update(&nokkuv1.WorkspaceSettings{})), "other settings stay free")
	assert.False(t, requestedFresh(&nokkuv1.GetVersionRequest{}), "another call")

	assert.True(t, requestedFresh(&nokkuv1.SetUserActiveRequest{Active: new(true)}), "reactivating")
	assert.False(t, requestedFresh(&nokkuv1.SetUserActiveRequest{Active: new(false)}), "deactivating stays quick")

	sa := func(paths ...string) *nokkuv1.UpdateServiceAccountRequest {
		return &nokkuv1.UpdateServiceAccountRequest{UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}}
	}
	assert.True(t, requestedFresh(sa("role")), "a service account's role")
	assert.False(t, requestedFresh(sa("name", "tags")), "a service account's name and tags stay free")

	daemon := func(paths ...string) *nokkuv1.UpdateDaemonRequest {
		return &nokkuv1.UpdateDaemonRequest{UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}}
	}
	assert.True(t, requestedFresh(daemon("config.record_sessions")), "turning recording off")
	assert.False(t, requestedFresh(daemon("status", "config.allow_forwarding")), "other daemon settings stay free")
}

// An uncapped create is unbounded when hosted, so each is capped or named here.
func TestEveryCreateIsCapped(t *testing.T) {
	for _, procedure := range allProcedures(t) {
		_, method, _ := strings.Cut(strings.TrimPrefix(procedure, "/"), "/")
		if !strings.HasPrefix(method, "Create") {
			continue
		}
		_, exempt := uncappedCreates[procedure]
		capped := procedureAccess[procedure].GetCapped()
		assert.NotEqual(t, exempt, capped, "%s: capped=%t, exempt=%t, want exactly one", procedure, capped, exempt)
	}
	for procedure := range uncappedCreates {
		assert.NotNil(t, procedureAccess[procedure], "uncappedCreates names %s, which does not exist", procedure)
	}
}
