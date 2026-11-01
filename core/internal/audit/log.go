package audit

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
)

const (
	// maxTarget is stored before the request is validated.
	maxTarget = 256
	// auditWriteTimeout bounds what a slow database adds to a request.
	auditWriteTimeout = 10 * time.Second
)

type eventKey struct{}

// targetStream reads the target at decode, before a handler can override it.
type targetStream struct {
	connect.ServerStream

	e *Event
}

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

// Intercept sits outside authorization, so denied calls are recorded too.
func (s *Service) Intercept(next connect.ServerFunc) connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
		if !Records(spec.Schema) {
			return next(ctx, spec, stream)
		}
		_, method, _ := strings.Cut(strings.TrimPrefix(spec.Procedure, "/"), "/")
		e := &Event{Action: method, Details: map[string]any{}}
		e.WorkspaceID = actor.WorkspaceIDFromContext(ctx)
		// A stream may receive past the handler, only unary names the target.
		if spec.StreamType == connect.StreamTypeUnary {
			stream = &targetStream{ServerStream: stream, e: e}
		}
		err := next(context.WithValue(ctx, eventKey{}, e), spec, stream)
		s.finish(ctx, e, err)
		return err
	}
}

func (t *targetStream) Receive(msg any) error {
	if err := t.ServerStream.Receive(msg); err != nil {
		return err
	}
	if m, ok := msg.(proto.Message); ok {
		t.e.Target = cut(requestTarget(m.ProtoReflect()), maxTarget)
	}
	return nil
}

// Records is false for calls the proto marks read-only or quiet.
func Records(schema any) bool {
	md, ok := schema.(protoreflect.MethodDescriptor)
	if !ok {
		return true
	}
	if opts, _ := md.Options().(*descriptorpb.MethodOptions); opts.GetIdempotencyLevel() == descriptorpb.MethodOptions_NO_SIDE_EFFECTS {
		return false
	}
	access, _ := proto.GetExtension(md.Options(), nokkuv1.E_Access).(*nokkuv1.Access)
	return !access.GetQuiet()
}

// Log is for work the interceptor cannot see, like a relay opening.
func (s *Service) Log(ctx context.Context, e *Event) {
	if e.WorkspaceID == "" {
		e.WorkspaceID = actor.WorkspaceIDFromContext(ctx)
	}
	s.finish(ctx, e, nil)
}

// Record is for sign-in flows, which have no principal yet and name the actor.
func (s *Service) Record(ctx context.Context, e *Event) {
	e.WorkspaceID = actor.WorkspaceIDFromContext(ctx)
	if e.WorkspaceID == "" {
		return
	}
	if meta, ok := actor.RequestMetaFromContext(ctx); ok {
		e.IP = meta.ClientIP()
		e.UserAgent = meta.UserAgent()
	}

	s.write(ctx, e)
}

// Commit writes the event now, for what leaves no other trace, like a
// certificate. The caller refuses on an error, so nothing goes out unlogged.
func (s *Service) Commit(ctx context.Context) error {
	e, ok := ctx.Value(eventKey{}).(*Event)
	if !ok {
		return errors.New("audit: this call has no event")
	}
	if err := s.Confirm(ctx, e); err != nil {
		return err
	}
	e.written = true
	return nil
}

// Confirm is Log for a caller that must refuse when the row can't be written.
func (s *Service) Confirm(ctx context.Context, e *Event) error {
	if e.WorkspaceID == "" {
		e.WorkspaceID = actor.WorkspaceIDFromContext(ctx)
	}
	s.stamp(ctx, e, nil)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()
	return s.Append(ctx, e)
}

// finish skips calls with no principal or workspace, sign-in records its own.
func (s *Service) finish(ctx context.Context, e *Event, err error) {
	p, _ := actor.PrincipalFromContext(ctx)
	if p.ID == "" || e.WorkspaceID == "" || e.written {
		return
	}
	s.stamp(ctx, e, err)
	s.write(ctx, e)
}

// A call with no principal keeps the actor the caller named.
func (s *Service) stamp(ctx context.Context, e *Event, err error) {
	p, _ := actor.PrincipalFromContext(ctx)
	if p.ID != "" {
		e.ActorID, e.ActorKind, e.ActorName = p.ID, string(p.Kind), cmp.Or(p.Email, p.Name)
	}
	if meta, ok := actor.RequestMetaFromContext(ctx); ok {
		e.IP = meta.ClientIP()
		e.UserAgent = meta.UserAgent()
	}
	e.OK = err == nil
	if err != nil {
		if e.Details == nil {
			e.Details = map[string]any{}
		}
		e.Details["code"] = connect.CodeOf(err).String()
	}

	if e.ActorName == "" && (p.Kind == actor.KindUser || p.Kind == actor.KindCLI) {
		if u, err := s.conn.Tenant().GetUser(ctx, p.ID); err == nil {
			e.ActorName = u.Email
		}
	}
}

// Runs before the answer, so neither shutdown nor a hang-up loses a row.
func (s *Service) write(ctx context.Context, e *Event) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()
	if err := s.Append(ctx, e); err != nil {
		slog.Error("failed to write audit log", "action", e.Action, "error", err)
	}
}

// requestTarget reads only id, name and *_id, so no secret reaches the log.
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
