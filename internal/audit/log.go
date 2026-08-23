package audit

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	"github.com/mizuchilabs/kagi"

	"github.com/nokku-sh/nokku/internal/util"
)

// anonActorID is the placeholder actor for events where no principal is
// authenticated (e.g. failed logins). The audit schema requires a non-null
// actor_id.
const anonActorID = "00000000-0000-0000-0000-000000000000"

// authProcedures are always audited, even when the request fails before
// any actor is known. Auth events are the core of a security audit trail.
var authProcedures = map[string]struct{}{
	"POST /auth/login":               {},
	"POST /auth/login/backup-code":   {},
	"POST /auth/logout":              {},
	"POST /auth/register":            {},
	"POST /auth/forgot-password":     {},
	"POST /auth/reset-password":      {},
	"POST /auth/verify-email":        {},
	"POST /auth/resend-verification": {},
	"GET /oauth/callback":            {},
	"GET /oauth/login":               {},
	"GET /oidc/login":                {},
	"GET /oidc/callback":             {},
	"GET /saml/login":                {},
	"POST /saml/acs":                 {},
}

func (s *Service) LogAction(
	ctx context.Context,
	req connect.AnyRequest,
	reqErr error,
) {
	s.logAudit(ctx, req.Spec().Procedure, req.Header(), req.Peer().Addr, statusCodeOf(reqErr))
}

func (s *Service) LogStreamingAction(
	ctx context.Context,
	conn connect.StreamingHandlerConn,
	reqErr error,
) {
	s.logAudit(
		ctx,
		conn.Spec().Procedure,
		conn.RequestHeader(),
		conn.Peer().Addr,
		statusCodeOf(reqErr),
	)
}

func (s *Service) LogHTTPAction(ctx context.Context, r *http.Request, statusCode int) {
	s.logAudit(ctx, r.Method+" "+r.URL.Path, r.Header, r.RemoteAddr, httpStatusStr(statusCode))
}

// httpStatusStr normalizes an HTTP status into the same audit status space as
// RPC and auth events: any 2xx is a success ("OK"), anything else is the
// numeric status code. This keeps the UI and SIEM rules uniform ("OK" always
// means success) instead of mixing "200" and "OK" for the same outcome.
func httpStatusStr(status int) string {
	if status >= 200 && status < 300 {
		return "OK"
	}
	return strconv.Itoa(status)
}

// statusCodeOf maps an RPC outcome to an explicit audit status: "OK" on
// success, the connect code string otherwise.
func statusCodeOf(err error) string {
	code := connect.CodeOf(err)
	if code == connect.CodeUnknown {
		return "OK"
	}
	return code.String()
}

func (s *Service) logAudit(
	ctx context.Context,
	procedure string,
	header http.Header,
	peerAddr string,
	statusCode string,
) {
	defer func() {
		if r := recover(); r != nil {
			slog.Debug("panic while writing audit log", "panic_type", fmt.Sprintf("%T", r))
		}
	}()

	if s == nil || !shouldAudit(procedure) {
		return
	}

	state := StateFromContext(ctx)
	principal, _ := kagi.PrincipalFromContext(ctx)

	actorID := principal.SubjectID
	actorType := string(principal.Kind)
	if actorID == "" && state != nil {
		actorID = state.UserID
	}
	if actorID == "" {
		actorID = anonActorID
		actorType = "anonymous"
	} else if actorType == "" {
		actorType = "user"
	}

	email := ""
	if state != nil {
		email = state.Email
	}

	// A request's workspace comes from the kagi context (the tenant resolved
	// from the request for user principals, or the principal's tenant for
	// machine identities). The state workspace is only a fallback for
	// unauthenticated flows (e.g. daemon enrollment) that pin a tenant that
	// is not on the context.
	workspaceID := WorkspaceIDFromContext(ctx)
	if state != nil && state.WorkspaceID != "" {
		workspaceID = state.WorkspaceID
	}

	log := &Event{
		WorkspaceID: workspaceID,
		ActorID:     actorID,
		ActorType:   actorType,
		ActorEmail:  email,
		Action:      procedure,
		IPAddress:   util.SanitizeUTF8(util.GetRemoteIP(header, peerAddr)),
		UserAgent:   util.SanitizeUTF8(header.Get("User-Agent")),
		StatusCode:  statusCode,
	}

	if err := s.Append(ctx, log); err != nil {
		slog.Warn("failed to write audit log", "error_type", fmt.Sprintf("%T", err))
	}
}

// shouldAudit reports whether a procedure produces an audit record:
// mutating operations plus authentication events.
func shouldAudit(procedure string) bool {
	if isMutatingProcedure(procedure) {
		return true
	}
	_, ok := authProcedures[procedure]
	return ok
}

func isMutatingProcedure(procedure string) bool {
	if method, _, ok := strings.Cut(procedure, " "); ok {
		switch method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			return true
		}
	}

	_, method, ok := strings.Cut(strings.TrimPrefix(procedure, "/"), "/")
	if !ok {
		return false
	}

	mutatingPrefixes := []string{
		"Create",
		"Update",
		"Delete",
		"Remove",
		"Add",
		"Set",
		"Rotate",
		"Refresh",
		"Revoke",
		"Enroll",
		"Invite",
		"Accept",
		"Reject",
		"Sign",
	}

	for _, prefix := range mutatingPrefixes {
		if strings.HasPrefix(method, prefix) {
			return true
		}
	}

	return false
}
