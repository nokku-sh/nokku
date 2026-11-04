package iam

// SCIM 2.0 under RLS. Only a SCIM token of the host's workspace gets in.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	"github.com/elimity-com/scim/schema"
	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/cache"
	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
)

const (
	scimMountPath = "/scim/v2"
	// Only a group with its members gets big, this fits tens of thousands.
	maxSCIMBody = 4 << 20
	// A server per syncing workspace, so a sync doesn't build one per request.
	scimServerTTL     = time.Hour
	scimServerEntries = 10_000
)

type SCIMFlow struct {
	svc     *Service
	servers *cache.TTL[string, scim.Server]
}

func SCIMBaseURL(ctx context.Context) string {
	return baseURL(ctx) + scimMountPath
}

func newSCIMFlow(svc *Service) *SCIMFlow {
	// Azure sends booleans as strings, which is not spec behavior.
	schema.SetAllowStringValues(true)
	return &SCIMFlow{svc: svc, servers: cache.New[string, scim.Server](scimServerEntries, scimServerTTL)}
}

func (s *Service) SCIMHandler() http.Handler {
	return http.HandlerFunc(s.SCIM.serve)
}

func (f *SCIMFlow) serve(w http.ResponseWriter, r *http.Request) {
	ws, ok := actor.WorkspaceFromContext(r.Context())
	scheme, raw, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		writeScimError(w, scimerrors.ScimError{Status: http.StatusUnauthorized, Detail: "authentication required"})
		return
	}
	p, tok, err := f.svc.AuthenticateToken(r.Context(), raw, crypto.TokenSCIM)
	// A provider reads 401 as a broken token, but retries a 500.
	if err != nil && !IsCredentialError(err) {
		writeScimError(w, scimerrors.ScimErrorInternal)
		return
	}
	if err != nil || p.Kind != actor.KindSCIM {
		writeScimError(w, scimerrors.ScimError{Status: http.StatusUnauthorized, Detail: "invalid token"})
		return
	}
	f.svc.noteSeen(r.Context(), tok)
	// Read here, the library drops a read error and reports bad JSON.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSCIMBody))
	if _, tooBig := errors.AsType[*http.MaxBytesError](err); tooBig {
		writeScimError(w, scimerrors.ScimError{
			Status: http.StatusRequestEntityTooLarge,
			Detail: "the request is over the 4 MiB limit, send the members of a group in smaller batches",
		})
		return
	}
	if err != nil {
		writeScimError(w, scimerrors.ScimError{Status: http.StatusBadRequest, Detail: "the request could not be read"})
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
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
	if s, ok := f.servers.Get(ws.ID); ok {
		return s, nil
	}
	s, err := scim.NewServer(
		&scim.ServerArgs{
			ServiceProviderConfig: &scim.ServiceProviderConfig{
				MaxResults:       100,
				SupportFiltering: true,
				SupportPatch:     true,
			},
			ResourceTypes: scimResourceTypes(f.svc, ws),
		},
		scim.WithBaseURL(ws.BaseURL+scimMountPath),
	)
	if err != nil {
		return scim.Server{}, err
	}
	f.servers.Set(ws.ID, s)
	return s, nil
}

// scimProvisionUser sets active on existing accounts too, the IdP owns it.
func (s *Service) scimProvisionUser(
	ctx context.Context,
	email, name string,
	active bool,
	externalID string,
) (*db.User, error) {
	var u *db.User
	var created, flipped bool
	err := s.conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		u, err = q.GetUserByEmail(ctx, email)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			u, err = s.createUser(ctx, q, db.CreateUserWithIDParams{Email: email, Name: name})
			if err != nil {
				return err
			}
			if err = q.SetUserSCIMManaged(ctx, u.ID); err != nil {
				return err
			}
			created = true
			if !active {
				if u, err = s.SetUserActive(ctx, q, u.ID, false); err != nil {
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
			if u, err = s.SetUserActive(ctx, q, u.ID, active); err != nil {
				return err
			}
			flipped = true
		}
		return linkSCIM(ctx, q, u.ID, externalID)
	})
	if err != nil {
		return nil, scimUserError(mapUserError(err))
	}
	if created {
		s.record(ctx, event{
			Action: actionUserCreated, Kind: actor.KindUser, Method: MethodSCIM, UserID: u.ID, Email: u.Email,
		})
	}
	if flipped {
		s.recordActive(ctx, u)
	}
	if !u.Active {
		if _, err := s.revokeSubject(ctx, u.ID); err != nil {
			return nil, err
		}
	}
	return u, nil
}

// requirePlan guards writes that let someone in, offboarding must work off the plan.
func (s *Service) requirePlan(ctx context.Context) error {
	if s.hasSCIM == nil {
		return nil
	}
	ok, err := s.hasSCIM(ctx, actor.WorkspaceIDFromContext(ctx))
	if err != nil {
		slog.Error("SCIM plan lookup failed", "error", err, "workspace_id", actor.WorkspaceIDFromContext(ctx))
		// A provider retries a 500, a 403 it does not.
		return scimerrors.ScimErrorInternal
	}
	if !ok {
		return scimerrors.ScimError{
			Status: http.StatusForbidden,
			Detail: "provisioning is not on this workspace's plan, only offboarding goes through",
		}
	}
	return nil
}

func scimUserError(err error) error {
	switch {
	case errors.Is(err, ErrSeatLimit):
		return scimerrors.ScimError{Status: http.StatusForbidden, Detail: err.Error()}
	case errors.Is(err, ErrEmailTaken):
		return scimerrors.ScimErrorUniqueness
	}
	return err
}

func (s *Service) recordActive(ctx context.Context, u *db.User) {
	a := actionUserDeactivated
	if u.Active {
		a = actionUserActivated
	}
	s.record(ctx, event{Action: a, Kind: actor.KindUser, Method: MethodSCIM, UserID: u.ID, Email: u.Email})
}

// linkSCIM replaces the stored id, IdP migrations change it.
func linkSCIM(ctx context.Context, q *db.Queries, userID, externalID string) error {
	if externalID == "" {
		return nil
	}
	err := q.SetUserSCIMExternalID(ctx, &db.SetUserSCIMExternalIDParams{ID: userID, ExternalID: &externalID})
	if db.IsUniqueViolation(err) {
		return scimerrors.ScimErrorBadRequest("externalId is already linked to another user")
	}
	return err
}

// keepOwner protects the owner, nobody else can hand the workspace on.
func keepOwner(ctx context.Context, q *db.Queries, userID string) error {
	owner, err := q.GetOwner(ctx)
	if err != nil {
		return err
	}
	if owner.ID == userID {
		return scimerrors.ScimError{
			Status: http.StatusConflict,
			Detail: "the workspace owner cannot be deactivated, deprovisioned or renamed, transfer ownership first",
		}
	}
	return nil
}

// scimDeprovisionUser keeps the data for a re-assignment.
func (s *Service) scimDeprovisionUser(ctx context.Context, u *db.User) error {
	var after *db.User
	err := s.conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		if err := keepOwner(ctx, q, u.ID); err != nil {
			return err
		}
		if after, err = s.SetUserActive(ctx, q, u.ID, false); err != nil {
			return err
		}
		if err := q.SetUserSCIMExternalID(ctx, &db.SetUserSCIMExternalIDParams{ID: u.ID}); err != nil {
			return err
		}
		_, err = q.DeleteSubjectTokens(ctx, u.ID)
		return err
	})
	if err != nil {
		return err
	}
	// IdPs PATCH an account off and delete it later, one deactivation.
	if after.Active != u.Active {
		s.recordActive(ctx, after)
	}
	return nil
}

func writeScimError(w http.ResponseWriter, e scimerrors.ScimError) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(e.Status)
	if body, err := e.MarshalJSON(); err == nil {
		_, _ = w.Write(body)
	}
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

func scimAttrString(v any) string {
	s, _ := v.(string)
	return s
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
