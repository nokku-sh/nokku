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

	"github.com/nokku-sh/nokku/internal/auth"
	"github.com/nokku-sh/nokku/internal/util"
)

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
	principal, _ := kagi.PrincipalFromContext(ctx)
	tenant, _ := kagi.TenantFromContext(ctx)

	log := &Event{
		WorkspaceID: string(tenant),
		ActorID:     principal.SubjectID,
		ActorType:   string(principal.Kind),
		ActorEmail:  s.actorEmail(ctx, principal),
		Action:      procedure,
		IPAddress:   util.SanitizeUTF8(util.GetRemoteIP(header, peerAddr)),
		UserAgent:   util.SanitizeUTF8(header.Get("User-Agent")),
		StatusCode:  statusCode,
	}

	if err := s.Append(ctx, log); err != nil {
		slog.Warn("failed to write audit log", "error_type", fmt.Sprintf("%T", err))
	}
}

// actorEmail resolves the acting human's email for display. Machine subjects
// are not users; their rows carry no email. The lookup runs off the request
// path (logAudit is called from a detached goroutine) and a miss simply leaves
// the column empty.
func (s *Service) actorEmail(ctx context.Context, p kagi.Principal) string {
	if s.users == nil ||
		p.SubjectID == "" ||
		(p.Kind != auth.ActorTypeUser && p.Kind != auth.ActorTypeDevice) {
		return ""
	}
	u, err := s.users.GetUser(ctx, p.SubjectID)
	if err != nil {
		return ""
	}
	return u.Email
}

// shouldAudit reports whether a procedure produces an audit record. Only
// mutating operations do: authentication flows record their own semantic
// events (login_success, login_denied, ...) through the kagi sink.
func shouldAudit(procedure string) bool {
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
