package iam

// SCIM 2.0 at /scim/v2 of the workspace host. The request runs in the
// workspace its host names, under RLS like any tenant request, and only a
// SCIM token of that workspace gets in.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	"github.com/elimity-com/scim/schema"
	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/db"
)

const scimMountPath = "/scim/v2"

type SCIMFlow struct {
	svc     *Service
	mu      sync.Mutex
	servers map[string]scim.Server
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
	ws, ok := actor.WorkspaceFromContext(r.Context())
	raw, hasToken := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !hasToken {
		writeScimError(w, scimerrors.ScimError{Status: http.StatusUnauthorized, Detail: "authentication required"})
		return
	}
	p, tok, err := f.svc.AuthenticateToken(r.Context(), raw)
	if err != nil || p.Kind != actor.KindSCIM {
		writeScimError(w, scimerrors.ScimError{Status: http.StatusUnauthorized, Detail: "invalid token"})
		return
	}
	f.svc.noteSeen(r.Context(), tok)
	server, err := f.serverFor(ws)
	if err != nil {
		writeScimError(w, scimerrors.ScimErrorInternal)
		return
	}

	ctx := actor.ContextWithPrincipal(r.Context(), p)
	r = r.WithContext(ctx)
	r.URL.Path = "/" + strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, scimMountPath), "/")
	server.ServeHTTP(w, r)
}

func (f *SCIMFlow) serverFor(ws actor.Workspace) (scim.Server, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.servers[ws.ID]; ok {
		return s, nil
	}
	s, err := scim.NewServer(
		&scim.ServerArgs{
			ServiceProviderConfig: &scim.ServiceProviderConfig{},
			ResourceTypes:         scimResourceTypes(f.svc, ws),
		},
		scim.WithBaseURL(ws.BaseURL+scimMountPath),
	)
	if err != nil {
		return scim.Server{}, err
	}
	f.servers[ws.ID] = s
	return s, nil
}

// scimProvisionUser applies active to existing accounts too, the IdP is the
// source of truth.
func (s *Service) scimProvisionUser(
	ctx context.Context,
	email, name string,
	active bool,
	externalID string,
) (*db.User, error) {
	var u *db.User
	var created bool
	err := s.conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		u, err = q.GetUserByEmail(ctx, email)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			u, err = s.createUser(ctx, q, db.CreateUserWithIDParams{Email: email, Name: name}, "")
			if errors.Is(err, ErrSeatLimit) {
				return scimerrors.ScimError{Status: http.StatusForbidden, Detail: err.Error()}
			}
			if err != nil {
				return err
			}
			created = true
			if !active {
				if u, err = setUserActive(ctx, q, u.ID, false); err != nil {
					return err
				}
			}
		case err != nil:
			return err
		case u.Active != active:
			if !active {
				if err := keepOwner(ctx, q, u.ID); err != nil {
					return err
				}
			}
			if u, err = setUserActive(ctx, q, u.ID, active); err != nil {
				return err
			}
		}
		return linkSCIMCredential(ctx, q, u.ID, externalID)
	})
	if err != nil {
		return nil, mapUserError(err)
	}
	if created {
		s.record(ctx, event{
			Action: actionUserCreated, Kind: actor.KindUser, Method: MethodSCIM, UserID: u.ID, Email: u.Email,
		})
	}
	if !u.Active {
		if _, err := s.revokeSubject(ctx, u.ID); err != nil {
			return nil, err
		}
	}
	return u, nil
}

func setUserActive(ctx context.Context, q *db.Queries, userID string, active bool) (*db.User, error) {
	if err := q.SetUserActive(ctx, &db.SetUserActiveParams{ID: userID, Active: active}); err != nil {
		return nil, err
	}
	return q.GetUser(ctx, userID)
}

func linkSCIMCredential(ctx context.Context, q *db.Queries, userID, externalID string) error {
	if externalID == "" {
		return nil
	}
	// IdP migrations change the externalId, so one account never carries two links.
	if err := q.DeleteStaleUserSCIMCredentials(ctx, &db.DeleteStaleUserSCIMCredentialsParams{
		UserID:  userID,
		Subject: externalID,
	}); err != nil {
		return err
	}
	_, err := q.UpsertCredential(ctx, &db.UpsertCredentialParams{
		ID:      "scim:" + actor.WorkspaceIDFromContext(ctx) + ":" + externalID,
		UserID:  userID,
		Type:    string(MethodSCIM),
		Subject: externalID,
		Data:    []byte{},
	})
	if errors.Is(err, pgx.ErrNoRows) || db.IsUniqueViolation(err) {
		return scimerrors.ScimErrorBadRequest("externalId is already linked to another user")
	}
	return err
}

// keepOwner refuses to switch off or remove the owner. Nobody else can hand
// the workspace on.
func keepOwner(ctx context.Context, q *db.Queries, userID string) error {
	owner, err := q.GetOwner(ctx)
	if err != nil {
		return err
	}
	if owner.ID == userID {
		return scimerrors.ScimError{
			Status: http.StatusConflict,
			Detail: "the workspace owner cannot be deactivated or deprovisioned, transfer ownership first",
		}
	}
	return nil
}

// scimDeprovisionUser deactivates the account and drops its IdP link. The
// data survives for an IdP re-assignment.
func (s *Service) scimDeprovisionUser(ctx context.Context, u *db.User) error {
	err := s.conn.TenantTx(ctx, func(q *db.Queries) error {
		if err := keepOwner(ctx, q, u.ID); err != nil {
			return err
		}
		if _, err := setUserActive(ctx, q, u.ID, false); err != nil {
			return err
		}
		if err := q.DeleteUserSCIMCredentials(ctx, u.ID); err != nil {
			return err
		}
		_, err := q.DeleteSubjectTokens(ctx, u.ID)
		return err
	})
	if err != nil {
		return err
	}
	s.record(ctx, event{
		Action: actionUserDeactivated, Kind: actor.KindUser, Method: MethodSCIM, UserID: u.ID, Email: u.Email,
	})
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
