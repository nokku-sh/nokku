package audit

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/nokku-sh/nokku/internal/iam"
	"github.com/nokku-sh/nokku/internal/util"
)

// skipPrefixes marks methods that are not audit events: reads, polling syncs,
// and long-lived transport streams.
var skipPrefixes = []string{
	"Get", "List", "Whoami", "Subscribe", "Sync", "Connect", "Relay", "DaemonRelay",
}

type eventKey struct{}

// SetTarget names the resource the current request acted on, for handlers
// whose request carries no id yet, such as a create.
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

// WrapUnary audits every RPC that is not a read. The action is the method
// name and the target comes from the request's id, name, or first *_id field.
func (s *Service) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		e := newEvent(req.Spec().Procedure)
		if e == nil {
			return next(ctx, req)
		}
		if msg, ok := req.Any().(proto.Message); ok {
			e.Target = requestTarget(msg.ProtoReflect())
		}
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
		err := next(context.WithValue(ctx, eventKey{}, e), conn)
		s.finish(ctx, e, conn.RequestHeader(), conn.Peer().Addr, err)
		return err
	}
}

// newEvent starts the event for a procedure, or returns nil when the
// procedure is not audited.
func newEvent(procedure string) *Event {
	_, method, _ := strings.Cut(strings.TrimPrefix(procedure, "/"), "/")
	for _, prefix := range skipPrefixes {
		if strings.HasPrefix(method, prefix) {
			return nil
		}
	}
	return &Event{Action: method, Details: map[string]any{}}
}

// Log records an event a handler emits itself, for work the interceptor
// cannot see, like a relay opening or recording content being read. Actor
// and transport facts come from ctx. The event counts as a success.
func (s *Service) Log(ctx context.Context, e *Event) {
	var header http.Header
	var peer string
	if meta, ok := iam.RequestMetaFromContext(ctx); ok {
		header, peer = meta.Header, meta.RemoteAddr
	}
	if e.WorkspaceID == "" {
		e.WorkspaceID = iam.WorkspaceIDFromContext(ctx)
	}
	s.finish(ctx, e, header, peer, nil)
}

// finish fills in who, where, and the outcome, then writes the event off the
// request path. Unauthenticated calls are skipped: the auth flows record
// their own events through the iam sink.
func (s *Service) finish(ctx context.Context, e *Event, header http.Header, peer string, err error) {
	p, _ := iam.PrincipalFromContext(ctx)
	if p.ID == "" {
		return
	}
	e.Timestamp = time.Now().UTC()
	if e.WorkspaceID == "" {
		e.WorkspaceID = iam.WorkspaceIDFromContext(ctx)
	}
	e.ActorID, e.ActorKind, e.ActorName = p.ID, string(p.Kind), p.Email
	if header != nil {
		e.IP = util.SanitizeUTF8(util.GetRemoteIP(header, peer))
		e.UserAgent = util.SanitizeUTF8(header.Get("User-Agent"))
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
		if e.ActorName == "" && (p.Kind == iam.KindUser || p.Kind == iam.KindCLI) {
			if u, err := s.conn.Sys().GetUser(actx, p.ID); err == nil {
				e.ActorName = u.Email
			}
		}
		if err := s.Append(actx, e); err != nil {
			slog.Warn("failed to write audit log", "action", e.Action, "error", err)
		}
	}()
}

// requestTarget picks the resource a request is about: its id, else its
// name, else its first other *_id field. Only these fields are read, so no
// secret in the request can reach the log.
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

func stringField(msg protoreflect.Message, fd protoreflect.FieldDescriptor) string {
	if fd == nil || fd.Kind() != protoreflect.StringKind || fd.IsList() || !msg.Has(fd) {
		return ""
	}
	return msg.Get(fd).String()
}
