package audit

import (
	"cmp"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/realip"
)

// skipPrefixes are reads, polling syncs, and long-lived streams.
var skipPrefixes = []string{
	"Get", "List", "Whoami", "Subscribe", "Sync", "Connect", "Relay", "DaemonRelay",
}

// Both are stored before the request is validated.
const (
	maxTarget    = 256
	maxUserAgent = 512
)

type eventKey struct{}

// SetTarget is for requests without an id yet, like a create.
func SetTarget(ctx context.Context, target string) {
	if e, ok := ctx.Value(eventKey{}).(*Event); ok {
		e.Target = target
	}
}

// Set adds a detail to the current request's audit event. Never pass secrets.
func Set(ctx context.Context, key string, value any) {
	if e, ok := ctx.Value(eventKey{}).(*Event); ok {
		e.Details[key] = value
	}
}

func (s *Service) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		e := newEvent(req.Spec().Procedure)
		if e == nil {
			return next(ctx, req)
		}
		if msg, ok := req.Any().(proto.Message); ok {
			e.Target = cut(requestTarget(msg.ProtoReflect()), maxTarget)
		}
		e.WorkspaceID = actor.WorkspaceIDFromContext(ctx)
		resp, err := next(context.WithValue(ctx, eventKey{}, e), req)
		s.finish(ctx, e, req.Header(), req.Peer().Addr, err)
		return resp, err
	}
}

func (s *Service) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (s *Service) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		e := newEvent(conn.Spec().Procedure)
		if e == nil {
			return next(ctx, conn)
		}
		e.WorkspaceID = actor.WorkspaceIDFromContext(ctx)
		err := next(context.WithValue(ctx, eventKey{}, e), conn)
		s.finish(ctx, e, conn.RequestHeader(), conn.Peer().Addr, err)
		return err
	}
}

func newEvent(procedure string) *Event {
	_, method, _ := strings.Cut(strings.TrimPrefix(procedure, "/"), "/")
	for _, prefix := range skipPrefixes {
		if strings.HasPrefix(method, prefix) {
			return nil
		}
	}
	return &Event{Action: method, Details: map[string]any{}}
}

// Log is for work the interceptor cannot see, like a relay opening.
func (s *Service) Log(ctx context.Context, e *Event) {
	var header http.Header
	var peer string
	if meta, ok := actor.RequestMetaFromContext(ctx); ok {
		header, peer = meta.Header, meta.RemoteAddr
	}
	if e.WorkspaceID == "" {
		e.WorkspaceID = actor.WorkspaceIDFromContext(ctx)
	}
	s.finish(ctx, e, header, peer, nil)
}

// Record is for the sign-in flows. They run before there is a principal, so the caller names the actor.
func (s *Service) Record(ctx context.Context, e *Event) {
	e.WorkspaceID = actor.WorkspaceIDFromContext(ctx)
	if e.WorkspaceID == "" {
		return
	}
	e.Timestamp = time.Now().UTC()
	if meta, ok := actor.RequestMetaFromContext(ctx); ok {
		e.IP = strings.ToValidUTF8(realip.Bucket(meta.Header, meta.RemoteAddr), "")
		e.UserAgent = cut(strings.ToValidUTF8(meta.Header.Get("User-Agent"), ""), maxUserAgent)
	}

	// Detached so a slow DB cannot stall a login.
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	go func() {
		defer cancel()
		if err := s.Append(actx, e); err != nil {
			slog.Warn("failed to write auth audit log", "action", e.Action, "error", err)
		}
	}()
}

// finish skips unauthenticated calls and calls outside a workspace, the sign-in flows record their own.
func (s *Service) finish(ctx context.Context, e *Event, header http.Header, peer string, err error) {
	p, _ := actor.PrincipalFromContext(ctx)
	if p.ID == "" || e.WorkspaceID == "" {
		return
	}
	e.Timestamp = time.Now().UTC()
	e.ActorID, e.ActorKind, e.ActorName = p.ID, string(p.Kind), cmp.Or(p.Email, p.Name)
	if header != nil {
		e.IP = strings.ToValidUTF8(realip.Bucket(header, peer), "")
		e.UserAgent = cut(strings.ToValidUTF8(header.Get("User-Agent"), ""), maxUserAgent)
	}
	e.OK = err == nil
	if err != nil {
		if e.Details == nil {
			e.Details = map[string]any{}
		}
		e.Details["code"] = connect.CodeOf(err).String()
	}

	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	go func() {
		defer cancel()
		if e.ActorName == "" && (p.Kind == actor.KindUser || p.Kind == actor.KindCLI) {
			if u, err := s.conn.Tenant().GetUser(actx, p.ID); err == nil {
				e.ActorName = u.Email
			}
		}
		if err := s.Append(actx, e); err != nil {
			slog.Warn("failed to write audit log", "action", e.Action, "error", err)
		}
	}()
}

// requestTarget reads only id, name and *_id fields, so no secret in the request can reach the log.
func requestTarget(msg protoreflect.Message) string {
	fields := msg.Descriptor().Fields()
	for _, name := range []protoreflect.Name{"id", "name"} {
		if v := stringField(msg, fields.ByName(name)); v != "" {
			return v
		}
	}
	for i := range fields.Len() {
		fd := fields.Get(i)
		if fd.Name() != "workspace_id" && strings.HasSuffix(string(fd.Name()), "_id") {
			if v := stringField(msg, fd); v != "" {
				return v
			}
		}
	}
	return ""
}

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

func stringField(msg protoreflect.Message, fd protoreflect.FieldDescriptor) string {
	if fd == nil || fd.Kind() != protoreflect.StringKind || fd.IsList() || !msg.Has(fd) {
		return ""
	}
	return msg.Get(fd).String()
}
