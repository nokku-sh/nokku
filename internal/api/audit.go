package api

import (
	"context"
	"net/http"
	"time"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/audit"
)

// auditDetach bounds the audit write so a stalled DB connection can't pin an
// async goroutine forever. The detached (non-cancellable) context preserves
// audit integrity for completed requests.
func auditDetach(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
}

type AuditInterceptor struct {
	audit *audit.Service
}

func NewAuditInterceptor(audit *audit.Service) *AuditInterceptor {
	return &AuditInterceptor{audit: audit}
}

func (a *AuditInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		resp, err := next(ctx, req)
		go func() {
			actx, cancel := auditDetach(ctx)
			defer cancel()
			a.audit.LogAction(actx, req, err)
		}()
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
		err := next(ctx, conn)
		go func() {
			actx, cancel := auditDetach(ctx)
			defer cancel()
			a.audit.LogStreamingAction(actx, conn, err)
		}()
		return err
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
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		go func() {
			actx, cancel := auditDetach(r.Context())
			defer cancel()
			a.audit.LogHTTPAction(actx, r, sw.status)
		}()
	})
}
