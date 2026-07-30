package audit

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"github.com/nokku-sh/nokku/internal/meta"
	"github.com/nokku-sh/nokku/internal/util"
)

func (s *Service) LogAction(
	ctx context.Context,
	req connect.AnyRequest,
	reqErr error,
) {
	code := connect.CodeOf(reqErr)
	statusCode := ""
	if code != connect.CodeUnknown {
		statusCode = code.String()
	}
	s.logAudit(ctx, req.Spec().Procedure, req.Header(), req.Peer().Addr, statusCode)
}

func (s *Service) LogStreamingAction(
	ctx context.Context,
	conn connect.StreamingHandlerConn,
	reqErr error,
) {
	code := connect.CodeOf(reqErr)
	statusCode := ""
	if code != connect.CodeUnknown {
		statusCode = code.String()
	}
	s.logAudit(ctx, conn.Spec().Procedure, conn.RequestHeader(), conn.Peer().Addr, statusCode)
}

func (s *Service) LogHTTPAction(ctx context.Context, r *http.Request, statusCode int) {
	s.logAudit(ctx, r.Method+" "+r.URL.Path, r.Header, r.RemoteAddr, strconv.Itoa(statusCode))
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
			slog.Debug("panic in audit log", "recover", r)
		}
	}()

	if s == nil {
		return
	}

	if !isMutatingProcedure(procedure) {
		return
	}

	state := meta.AuditStateFromContext(ctx)
	actor := meta.ActorFromContext(ctx)

	if actor.ID == "" || state == nil {
		return
	}

	log := &Event{
		WorkspaceID: state.WorkspaceID,
		ActorID:     actor.ID,
		ActorType:   string(actor.Type),
		Action:      procedure,
		IPAddress:   util.SanitizeUTF8(sourceIP(header, peerAddr)),
		UserAgent:   util.SanitizeUTF8(header.Get("User-Agent")),
		StatusCode:  statusCode,
	}

	if err := s.Append(ctx, log); err != nil {
		slog.Debug("failed to create audit log", "error", err)
	}
}

func sourceIP(header http.Header, peerAddr string) string {
	if ip := header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if xff := header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}
	if peerAddr != "" {
		if host, _, err := net.SplitHostPort(peerAddr); err == nil {
			return host
		}
		return peerAddr
	}
	return "unknown"
}

func isMutatingProcedure(procedure string) bool {
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
