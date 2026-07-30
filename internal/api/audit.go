package api

import (
	"context"
	"net/http"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/audit"
	"github.com/nokku-sh/nokku/internal/meta"
)

type AuditInterceptor struct {
	audit *audit.Service
}

func NewAuditInterceptor(audit *audit.Service) *AuditInterceptor {
	return &AuditInterceptor{audit: audit}
}

func (a *AuditInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		ctx = meta.WithAuditState(ctx, &meta.AuditState{UserID: meta.UserIDFromContext(ctx)})
		resp, err := next(ctx, req)
		go a.audit.LogAction(context.WithoutCancel(ctx), req, err)
		return resp, err
	}
}

func (a *AuditInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return next
}

func (a *AuditInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		ctx = meta.WithAuditState(ctx, &meta.AuditState{UserID: meta.UserIDFromContext(ctx)})
		go a.audit.LogStreamingAction(context.WithoutCancel(ctx), conn, nil)
		return next(ctx, conn)
	}
}

// HTTP wrappers --------------------------------------------------------------

type statusWriter struct {
	http.ResponseWriter

	status int
}

func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (a *AuditInterceptor) WithAudit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := meta.WithAuditState(
			r.Context(),
			&meta.AuditState{UserID: meta.UserIDFromContext(r.Context())},
		)
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r.WithContext(ctx))
		go a.audit.LogHTTPAction(context.WithoutCancel(ctx), r, sw.status)
	})
}
