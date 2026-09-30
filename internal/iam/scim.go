package iam

// SCIM 2.0 at /scim/v2/{workspace_id}. A verified token pins the request to
// its workspace, so it runs under RLS like any tenant request. A connector
// only ever touches accounts under its workspace's verified domains.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	"github.com/elimity-com/scim/schema"
	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

const scimMountPath = "/scim/v2"

var errSCIMUnmanaged = scimerrors.ScimErrorBadRequest("userName must be in a verified domain of this workspace")

type SCIMFlow struct {
	svc     *Service
	mu      sync.Mutex
	servers map[string]scim.Server
}

type SCIMToken struct {
	ID         string
	Label      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

func newSCIMFlow(svc *Service) *SCIMFlow {
	// Azure sends booleans as strings, which is not spec behavior.
	schema.SetAllowStringValues(true)
	return &SCIMFlow{svc: svc, servers: map[string]scim.Server{}}
}

func (s *Service) SCIMHandler() http.Handler {
	return http.HandlerFunc(s.SCIM.serve)
}

func (f *SCIMFlow) serve(w http.ResponseWriter, r *http.Request) {
	rest, _ := strings.CutPrefix(r.URL.Path, scimMountPath+"/")
	workspaceID, tail, _ := strings.Cut(rest, "/")
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || workspaceID == "" {
		writeScimError(w, scimerrors.ScimError{Status: http.StatusUnauthorized, Detail: "authentication required"})
		return
	}
	tokenID, err := f.svc.verifySCIMToken(r.Context(), workspaceID, raw)
	if err != nil {
		writeScimError(w, scimerrors.ScimError{Status: http.StatusUnauthorized, Detail: "invalid token"})
		return
	}
	server, err := f.serverFor(workspaceID)
	if err != nil {
		writeScimError(w, scimerrors.ScimErrorInternal)
		return
	}

	ctx := actor.ContextWithPrincipal(
		r.Context(),
		actor.Principal{ID: tokenID, Kind: actor.KindSCIM, WorkspaceID: workspaceID},
	)
	ctx = actor.AnnotateTenant(ctx, workspaceID)
	ctx = actor.WithMember(ctx, workspaceID, "")
	r = r.WithContext(ctx)
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

func (s *Service) verifySCIMToken(ctx context.Context, workspaceID, raw string) (string, error) {
	parsed, err := crypto.Parse(raw)
	if err != nil || parsed.ID != workspaceID {
		return "", errInvalidToken
	}
	hash, err := crypto.HashToken(raw)
	if err != nil {
		return "", errInvalidToken
	}
	row, err := s.sys.GetSCIMTokenByHash(ctx, hash)
	if err != nil || row.WorkspaceID != workspaceID {
		return "", errInvalidToken
	}
	_ = s.sys.TouchSCIMToken(ctx, row.ID)
	return row.ID, nil
}

func (s *Service) IssueSCIMToken(ctx context.Context, workspaceID, label string) (SCIMToken, string, error) {
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

func (s *Service) ListSCIMTokens(ctx context.Context, workspaceID string) ([]SCIMToken, error) {
	var out []SCIMToken
	err := s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		rows, err := q.ListWorkspaceSCIMTokens(ctx, workspaceID)
		for _, r := range rows {
			out = append(out, SCIMToken{ID: r.ID, Label: r.Label, CreatedAt: r.CreatedAt, LastUsedAt: r.LastUsedAt})
		}
		return err
	})
	return out, err
}

func (s *Service) RevokeSCIMToken(ctx context.Context, workspaceID, tokenID string) error {
	return s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.DeleteSCIMToken(ctx, &db.DeleteSCIMTokenParams{ID: tokenID, WorkspaceID: workspaceID})
	})
}

// scimProvisionUser applies active to existing accounts too, the IdP is the
// source of truth.
func (s *Service) scimProvisionUser(
	ctx context.Context,
	workspaceID, email, name string,
	active bool,
	externalID string,
) (*db.User, error) {
	managed, err := s.managedBy(ctx, workspaceID, email)
	if err != nil {
		return nil, err
	}
	if !managed {
		return nil, errSCIMUnmanaged
	}

	var u *db.User
	var created bool
	err = s.conn.WithTx(ctx, func(q *db.Queries) error {
		u, err = q.GetUserByEmail(ctx, email)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if u, err = q.CreateUser(ctx, &db.CreateUserParams{Email: email, Name: name}); err != nil {
				return err
			}
			if err := q.VerifyUserEmail(ctx, u.ID); err != nil {
				return err
			}
			// Org-managed accounts get no self-serve password reset.
			if u, err = q.UpdateUser(ctx, &db.UpdateUserParams{
				ID:                   u.ID,
				Active:               &active,
				DisablePasswordReset: new(true),
			}); err != nil {
				return err
			}
			created = true
		case err != nil:
			return err
		case u.Active != active:
			if u, err = q.UpdateUser(ctx, &db.UpdateUserParams{ID: u.ID, Active: &active}); err != nil {
				return err
			}
		}
		if err := s.EnsureMember(ctx, q, u.ID, workspaceID, ""); err != nil {
			if errors.Is(err, errSeatLimit) {
				return scimerrors.ScimError{Status: http.StatusForbidden, Detail: err.Error()}
			}
			return err
		}
		return linkSCIMCredential(ctx, q, workspaceID, u.ID, externalID)
	})
	if err != nil {
		return nil, mapUserError(err)
	}
	if created {
		s.record(ctx, Event{
			Action:      ActionUserCreated,
			Kind:        actor.KindUser,
			Method:      MethodSCIM,
			UserID:      u.ID,
			Email:       u.Email,
			WorkspaceID: workspaceID,
		})
	}
	if !u.Active {
		if _, err := s.revokeSubject(ctx, u.ID); err != nil {
			return nil, err
		}
	}
	return u, nil
}

func linkSCIMCredential(ctx context.Context, q db.Querier, workspaceID, userID, externalID string) error {
	if externalID == "" {
		return nil
	}
	// IdP migrations change the externalId, so one account never carries two links.
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
	if errors.Is(err, pgx.ErrNoRows) || db.IsUniqueViolation(err) {
		return scimerrors.ScimErrorBadRequest("externalId is already linked to another user")
	}
	return err
}

// scimDeprovisionUser deletes an account left in no workspace. One still in
// other workspaces is deactivated everywhere, since the org owns the domain,
// and its data survives for an IdP re-assignment.
func (s *Service) scimDeprovisionUser(ctx context.Context, workspaceID string, u *db.User) error {
	var deleted bool
	err := s.conn.WithTx(ctx, func(q *db.Queries) error {
		owner, err := q.GetWorkspaceOwner(ctx, workspaceID)
		if err != nil {
			return err
		}
		if owner == u.ID {
			return scimerrors.ScimError{
				Status: http.StatusConflict,
				Detail: "the workspace owner cannot be deprovisioned, transfer ownership first",
			}
		}
		if err := q.RemoveWorkspaceMember(
			ctx,
			&db.RemoveWorkspaceMemberParams{WorkspaceID: workspaceID, UserID: u.ID},
		); err != nil {
			return err
		}
		if err := q.DeleteUserSCIMCredentials(
			ctx,
			&db.DeleteUserSCIMCredentialsParams{UserID: u.ID, WorkspaceID: workspaceID},
		); err != nil {
			return err
		}
		others, err := q.CountUserMemberships(ctx, u.ID)
		if err != nil {
			return err
		}
		if others == 0 {
			deleted = true
			return q.DeleteUser(ctx, u.ID)
		}
		if _, err := q.UpdateUser(ctx, &db.UpdateUserParams{ID: u.ID, Active: new(false)}); err != nil {
			return err
		}
		_, err = q.DeleteSubjectSessions(ctx, u.ID)
		return err
	})
	if err != nil {
		return err
	}
	e := Event{
		Action:      ActionUserDeactivated,
		Kind:        actor.KindUser,
		Method:      MethodSCIM,
		UserID:      u.ID,
		Email:       u.Email,
		WorkspaceID: workspaceID,
	}
	if deleted {
		e.Action = ActionUserDeleted
	}
	s.record(ctx, e)
	return nil
}

func writeScimError(w http.ResponseWriter, e scimerrors.ScimError) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(e.Status)
	if body, err := e.MarshalJSON(); err == nil {
		_, _ = w.Write(body)
	}
}

func scimAttrString(v any) string {
	s, _ := v.(string)
	return s
}

func scimAttrBool(v any, def bool) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}

func scimDisplayName(displayName, name any) string {
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
	return strings.TrimSpace(scimAttrString(m["givenName"]) + " " + scimAttrString(m["familyName"]))
}

func scimMemberRefs(v any) []string {
	list, _ := v.([]any)
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
