package iam

// SCIM 2.0 provisioning for workspaces (RFC 7642-7644). The protocol is
// served by github.com/elimity-com/scim; this package implements the
// ResourceHandler callbacks against the identity store and mounts the
// server at /scim/v2/{workspace_id}, the connector base URL IdP
// administrators paste into Okta or Azure.
//
// Auth is a workspace-scoped bearer token (scim_tokens). Requests carry no
// session principal, so every tenant-table access runs through WithTx
// (nokku_system) with the workspace bound in code: the token hash lookup
// pins the request to exactly one workspace and every handler passes that
// id into the query.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	"github.com/elimity-com/scim/schema"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

// mountPath is where hosts mount the SCIM handler. The workspace id is the
// next path segment and the rest is delegated to the elimity server.
const scimMountPath = "/scim/v2"

// SCIMFlow serves one SCIM endpoint per workspace. Servers are cached:
// they are immutable per workspace (static schemas, baseURL pinning the
// workspace), so construction happens once.
type SCIMFlow struct {
	svc *Service

	mu      sync.Mutex
	servers map[string]scim.Server
}

func newSCIMFlow(svc *Service) *SCIMFlow {
	// Azure's SCIM client sends booleans as strings; the library tolerates
	// it behind this flag, off by default because it is not spec behavior.
	schema.SetAllowStringValues(true)
	return &SCIMFlow{svc: svc, servers: map[string]scim.Server{}}
}

// SCIMHandler returns the [http.Handler] to mount at scimMountPath.
func (s *Service) SCIMHandler() http.Handler {
	return http.HandlerFunc(s.SCIM.serve)
}

func (f *SCIMFlow) serve(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, scimMountPath)
	rest = strings.TrimPrefix(rest, "/")
	if !ok || rest == "" {
		writeScimError(w, scimerrors.ScimErrorResourceNotFound(r.URL.Path))
		return
	}
	workspaceID, tail, _ := strings.Cut(rest, "/")

	raw := scimBearerToken(r)
	if raw == "" {
		writeScimError(w, scimerrors.ScimError{
			Status: http.StatusUnauthorized,
			Detail: "authentication required",
		})
		return
	}
	if err := f.svc.verifySCIMToken(r.Context(), workspaceID, raw); err != nil {
		writeScimError(w, scimerrors.ScimError{
			Status: http.StatusUnauthorized,
			Detail: "invalid token",
		})
		return
	}

	server, err := f.serverFor(workspaceID)
	if err != nil {
		writeScimError(w, scimerrors.ScimErrorInternal)
		return
	}
	// The elimity server dispatches on /Users, /Groups, /Schemas, ... and
	// trims a "/v2" prefix that is already gone here.
	r.URL.Path = "/" + tail
	server.ServeHTTP(w, r)
}

func (f *SCIMFlow) serverFor(workspaceID string) (scim.Server, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.servers[workspaceID]; ok {
		return s, nil
	}
	s, err := scim.NewServer(
		&scim.ServerArgs{
			ServiceProviderConfig: &scim.ServiceProviderConfig{},
			ResourceTypes:         scimResourceTypes(f.svc, workspaceID),
		},
		scim.WithBaseURL(f.svc.baseURL+scimMountPath+"/"+workspaceID),
	)
	if err != nil {
		return scim.Server{}, err
	}
	f.servers[workspaceID] = s
	return s, nil
}

func scimBearerToken(r *http.Request) string {
	const prefix = "Bearer "
	if v := r.Header.Get("Authorization"); strings.HasPrefix(v, prefix) {
		return strings.TrimPrefix(v, prefix)
	}
	return ""
}

// verifySCIMToken checks the bearer token against the store and pins it to
// the workspace in the URL: a valid token presented for another workspace
// is an invalid token. The row id returned by the throttled last-used
// touch is discarded; the touch keeps connector health visible.
func (s *Service) verifySCIMToken(ctx context.Context, workspaceID, raw string) error {
	parsed, err := crypto.Parse(raw)
	if err != nil || parsed.ID != workspaceID {
		return ErrInvalidToken
	}
	hash, err := crypto.HashToken(raw)
	if err != nil {
		return err
	}
	return s.conn.WithTx(ctx, func(q *db.Queries) error {
		row, err := q.GetSCIMTokenByHash(ctx, hash)
		if err != nil {
			return ErrInvalidToken
		}
		if row.WorkspaceID != workspaceID {
			return ErrInvalidToken
		}
		_ = q.TouchSCIMToken(ctx, row.ID)
		return nil
	})
}

// SCIMToken is a stored workspace connector token. The plaintext is never
// stored and only returned by IssueSCIMToken.
type SCIMToken struct {
	ID         string
	Label      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// IssueSCIMToken mints a workspace connector token. The plaintext is shown
// once, at creation; the store keeps only its hash.
func (s *Service) IssueSCIMToken(
	ctx context.Context,
	workspaceID, label string,
) (SCIMToken, string, error) {
	tok, err := crypto.NewToken(crypto.WithID(workspaceID))
	if err != nil {
		return SCIMToken{}, "", err
	}
	var out SCIMToken
	err = s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		row, err := q.CreateSCIMToken(ctx, &db.CreateSCIMTokenParams{
			WorkspaceID: workspaceID,
			TokenHash:   tok.Hash,
			Label:       label,
		})
		if err != nil {
			return err
		}
		out = SCIMToken{ID: row.ID, Label: row.Label, CreatedAt: row.CreatedAt}
		return nil
	})
	if err != nil {
		return SCIMToken{}, "", err
	}
	return out, tok.Plaintext, nil
}

// ListSCIMTokens lists the workspace's connector tokens, tenant-pinned.
func (s *Service) ListSCIMTokens(
	ctx context.Context,
	workspaceID string,
) ([]SCIMToken, error) {
	var out []SCIMToken
	err := s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		rows, err := q.ListWorkspaceSCIMTokens(ctx, workspaceID)
		if err != nil {
			return err
		}
		out = make([]SCIMToken, 0, len(rows))
		for _, r := range rows {
			out = append(out, SCIMToken{
				ID:         r.ID,
				Label:      r.Label,
				CreatedAt:  r.CreatedAt,
				LastUsedAt: r.LastUsedAt,
			})
		}
		return nil
	})
	return out, err
}

// RevokeSCIMToken deletes one connector token, tenant-pinned.
func (s *Service) RevokeSCIMToken(ctx context.Context, workspaceID, tokenID string) error {
	return s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.DeleteSCIMToken(ctx, &db.DeleteSCIMTokenParams{
			ID:          tokenID,
			WorkspaceID: workspaceID,
		})
	})
}

// scimProvisionUser resolves a SCIM identity: an existing user by email is
// joined into the workspace and re-linked, a new one is created
// (org-managed emails are trusted as verified, like SAML assertions). The
// active flag is applied to existing accounts too: an IdP re-assignment is
// the source of truth, so a deprovisioned employee pushed again comes back.
func (s *Service) scimProvisionUser(
	ctx context.Context,
	workspaceID, email, name string,
	active bool,
	externalID string,
) (*db.User, error) {
	u, err := s.GetUserByEmail(ctx, email)
	switch {
	case errors.Is(err, ErrNotFound):
		u, err = s.q.CreateUser(ctx, &db.CreateUserParams{Email: email, Name: name})
		if err != nil {
			return nil, mapUserError(err)
		}
		if err := s.VerifyUserEmail(ctx, u.ID); err != nil {
			return nil, err
		}
		// Org-managed accounts stay SSO-only: no self-serve password reset,
		// and inactive until the IdP says otherwise.
		if !active {
			inactive := false
			if u, err = s.UpdateUser(ctx, u.ID, UpdateUserPatch{Active: &inactive}); err != nil {
				return nil, err
			}
		}
		noReset := true
		if _, err := s.UpdateUser(
			ctx,
			u.ID,
			UpdateUserPatch{DisablePasswordReset: &noReset},
		); err != nil {
			return nil, err
		}
		s.record(ctx, Event{
			Action:      ActionUserCreated,
			Kind:        KindUser,
			Method:      MethodSCIM,
			UserID:      u.ID,
			Email:       u.Email,
			WorkspaceID: workspaceID,
		})
	case err != nil:
		return nil, err
	default:
		if u.Active != active {
			if u, err = s.UpdateUser(ctx, u.ID, UpdateUserPatch{Active: &active}); err != nil {
				return nil, err
			}
		}
	}

	err = s.conn.WithTx(ctx, func(q *db.Queries) error {
		// Same choke point as the invitation path: dormant today (SCIM is
		// Enterprise-only and Enterprise has no seat cap) but it wakes up the
		// moment the catalog ships a capped plan with SCIM. Re-syncs of
		// existing members skip the gate, a re-push must not fail because the
		// workspace filled up after a downgrade.
		if s.CanJoin != nil {
			if _, err := q.UserWorkspaceMember(ctx, &db.UserWorkspaceMemberParams{
				WorkspaceID: workspaceID,
				UserID:      u.ID,
			}); err != nil {
				if _, err := q.GetWorkspaceForUpdate(ctx, workspaceID); err != nil {
					return err
				}
				used, err := q.CountWorkspaceSeats(ctx, workspaceID)
				if err != nil {
					return err
				}
				if err := s.CanJoin(ctx, workspaceID, used); err != nil {
					return scimerrors.ScimError{Status: http.StatusForbidden, Detail: err.Error()}
				}
			}
		}

		if err := q.EnsureWorkspaceMember(ctx, &db.EnsureWorkspaceMemberParams{
			WorkspaceID: workspaceID,
			UserID:      u.ID,
		}); err != nil {
			return err
		}
		if externalID == "" {
			return nil
		}
		return linkSCIMCredential(ctx, q, workspaceID, u.ID, externalID)
	})
	if err != nil {
		return nil, err
	}
	return u, nil
}

func linkSCIMCredential(
	ctx context.Context,
	q db.Querier,
	workspaceID, userID, externalID string,
) error {
	// IdP-side identity migrations change the externalId: drop the old
	// mapping first so one account never carries two links.
	if err := q.DeleteStaleUserSCIMCredentials(ctx, &db.DeleteStaleUserSCIMCredentialsParams{
		UserID:      userID,
		WorkspaceID: workspaceID,
		Subject:     externalID,
	}); err != nil {
		return err
	}
	_, err := q.UpsertCredential(ctx, &db.UpsertCredentialParams{
		ID:       workspaceID + ":" + externalID,
		UserID:   userID,
		Type:     string(MethodSCIM),
		Provider: workspaceID,
		Subject:  externalID,
		Data:     []byte{},
	})
	if isUniqueViolation(err) {
		// The externalId is already bound to another account; the IdP must
		// not silently repoint one user's identity at a different one.
		return scimerrors.ScimErrorBadRequest("externalId is already linked to another user")
	}
	return err
}

// scimDeprovisionUser removes the user from the workspace and drops the
// SCIM identity link. The global account is deleted only when no other
// workspace still lists it and the user owns no workspace: SCIM DELETE
// must deprovision, and a full delete would reach across tenants or take
// an owned workspace down with it (created_by cascades).
//
// A user whose only trace is owned workspaces is the shadow-IT orphan:
// nothing may be deleted, but the account must not stay login-capable.
// It is deactivated instead (fail closed on every session), so the data
// survives for recovery while access dies, and an IdP re-assignment
// reactivates it.
func (s *Service) scimDeprovisionUser(ctx context.Context, workspaceID, userID string) error {
	u, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	var deleted, deactivated bool
	err = s.conn.WithTx(ctx, func(q *db.Queries) error {
		if err := q.RemoveWorkspaceMember(ctx, &db.RemoveWorkspaceMemberParams{
			WorkspaceID: workspaceID,
			UserID:      userID,
		}); err != nil {
			return err
		}
		if err := q.DeleteUserSCIMCredentials(ctx, &db.DeleteUserSCIMCredentialsParams{
			UserID:      userID,
			WorkspaceID: workspaceID,
		}); err != nil {
			return err
		}
		other, err := q.CountOtherUserMemberships(ctx, &db.CountOtherUserMembershipsParams{
			UserID:      userID,
			WorkspaceID: workspaceID,
		})
		if err != nil {
			return err
		}
		owned, err := q.CountWorkspacesCreatedBy(ctx, userID)
		if err != nil {
			return err
		}
		switch {
		case other == 0 && owned == 0:
			if err := q.DeleteUser(ctx, userID); err != nil {
				return err
			}
			deleted = true
		case other == 0 && u.Active:
			inactive := false
			if _, err := q.UpdateUser(
				ctx,
				&db.UpdateUserParams{ID: userID, Active: &inactive},
			); err != nil {
				return err
			}
			// Deactivation fails every session closed at the authn check;
			// dropping the rows keeps device listings honest too.
			if _, err := q.DeleteSubjectSessions(ctx, userID); err != nil {
				return err
			}
			deactivated = true
		}
		return nil
	})
	if err != nil {
		return err
	}
	switch {
	case deleted:
		s.record(ctx, Event{
			Action:      ActionUserDeleted,
			Kind:        KindUser,
			Method:      MethodSCIM,
			UserID:      userID,
			Email:       u.Email,
			WorkspaceID: workspaceID,
		})
	case deactivated:
		s.record(ctx, Event{
			Action:      ActionUserDeactivated,
			Kind:        KindUser,
			Method:      MethodSCIM,
			UserID:      userID,
			Email:       u.Email,
			WorkspaceID: workspaceID,
			Detail:      "owns workspaces; account kept and disabled",
		})
	}
	return nil
}

// writeScimError emits the library's SCIM error body.
func writeScimError(w http.ResponseWriter, e scimerrors.ScimError) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(e.Status)
	body, err := e.MarshalJSON()
	if err != nil {
		return
	}
	//nolint:gosec // the body is the library's marshaled SCIM error
	_, _ = w.Write(body)
}

func scimAttrString(v any) string {
	s, _ := v.(string)
	return s
}

func scimAttrBool(v any, def bool) bool {
	b, ok := v.(bool)
	if !ok {
		return def
	}
	return b
}

// scimDisplayName resolves the display name from the shapes IdPs send:
// a displayName string, a name object with formatted, or given+family.
func scimDisplayName(displayName any, name any) string {
	if s := scimAttrString(displayName); s != "" {
		return s
	}
	m, ok := name.(map[string]any)
	if !ok {
		return ""
	}
	if s := scimAttrString(m["formatted"]); s != "" {
		return s
	}
	given, family := scimAttrString(m["givenName"]), scimAttrString(m["familyName"])
	switch {
	case given != "" && family != "":
		return given + " " + family
	case given != "":
		return given
	default:
		return family
	}
}

// scimMemberRefs extracts the user ids an incoming members value carries.
func scimMemberRefs(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			if id := scimAttrString(m["value"]); id != "" {
				out = append(out, id)
			}
		}
	}
	return out
}

// scimRef builds a member $ref for list responses.
func scimRef(baseURL, endpoint, id string) string {
	return fmt.Sprintf("%s/%s/%s", baseURL, strings.TrimPrefix(endpoint, "/"), id)
}
