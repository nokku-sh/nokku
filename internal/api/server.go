// Package api contains the HTTP server for the nokku API.
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"runtime/debug"
	"strings"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/validate"

	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/entitlement"
	"github.com/nokku-sh/nokku/web"
)

// maxMessageBytes bounds one Connect message. The largest real ones are
// recording chunks and relay frames at 32 KiB.
const maxMessageBytes = 4 << 20

type Server struct {
	mux *http.ServeMux
	cfg *config.Config
}

func New(cfg *config.Config) *Server {
	return &Server{
		mux: http.NewServeMux(),
		cfg: cfg,
	}
}

func (s *Server) Start(ctx context.Context) error {
	s.registerServices(ctx)

	chain := newChain(
		s.withRateLimit,
		s.withHeaders,
		s.withCSRF,
		s.withLogger,
		s.withRecover,
		s.withTenant,
	)

	proto := new(http.Protocols)
	proto.SetHTTP1(true)
	proto.SetHTTP2(true)
	proto.SetUnencryptedHTTP2(true)
	server := &http.Server{
		BaseContext:       func(net.Listener) context.Context { return ctx },
		Addr:              "0.0.0.0:" + s.cfg.Port,
		Handler:           chain.then(s.mux),
		Protocols:         proto,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 14, // 16 KiB
	}

	serverErr := make(chan error, 1)
	go func() {
		slog.Info("server listening", "bind_address", server.Addr, "public_url", s.cfg.FullURL())
		if s.cfg.BootstrapLink != "" {
			slog.Warn("the owner has no passkey yet, sign in with this link, it works for 24 hours",
				"url", s.cfg.BootstrapLink)
		}
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	select {
	case <-ctx.Done():
		graceCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(graceCtx)

	case err := <-serverErr:
		return fmt.Errorf("server error: %w", err)
	}
}

func (s *Server) withHandlerOptions(ctx context.Context) []connect.HandlerOption {
	interceptors := []connect.Interceptor{
		newTimeoutInterceptor(),
		newAuthNInterceptor(s.cfg),
		s.cfg.Audit, // Audit wraps authorization so denied calls are recorded too.
		errorInterceptor{},
		newAuthZInterceptor(s.cfg),
		entitlement.NewGuardInterceptor(s.cfg.Entitlements),
		validate.NewInterceptor(),
		newOTLPInterceptor(ctx),
	}

	return []connect.HandlerOption{
		connect.WithCompressMinBytes(1024),
		connect.WithReadMaxBytes(maxMessageBytes),
		connect.WithInterceptors(interceptors...),
		connect.WithRecover(
			func(ctx context.Context, spec connect.Spec, _ http.Header, p any) error {
				attrs := []slog.Attr{
					slog.String("procedure", spec.Procedure),
					slog.String("panic_type", fmt.Sprintf("%T", p)),
				}
				if s.cfg.Debug {
					attrs = append(attrs, slog.String("stack", string(debug.Stack())))
				}
				slog.LogAttrs(ctx, slog.LevelError, "rpc panic recovered", attrs...)
				return errInternal
			},
		),
	}
}

// withTenant puts the workspace on the context. The health check and
// provider webhooks are not tied to a workspace host.
func (s *Server) withTenant(h http.Handler) http.Handler {
	resolved := s.cfg.Tenant.Middleware(h)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || strings.HasPrefix(r.URL.Path, "/webhooks/") {
			h.ServeHTTP(w, r)
			return
		}
		resolved.ServeHTTP(w, r)
	})
}

func (s *Server) registerServices(ctx context.Context) {
	opts := s.withHandlerOptions(ctx)
	s.mux.Handle(nokkuv1connect.NewWorkspaceServiceHandler(newWorkspaceService(s.cfg), opts...))
	s.mux.Handle(nokkuv1connect.NewDashboardServiceHandler(newDashboardService(s.cfg), opts...))
	s.mux.Handle(nokkuv1connect.NewTeamServiceHandler(newTeamService(s.cfg), opts...))
	s.mux.Handle(nokkuv1connect.NewUtilServiceHandler(newUtilService(s.cfg), opts...))
	s.mux.Handle(nokkuv1connect.NewTargetServiceHandler(newTargetService(s.cfg), opts...))
	s.mux.Handle(nokkuv1connect.NewPrincipalServiceHandler(newPrincipalService(s.cfg), opts...))
	s.mux.Handle(nokkuv1connect.NewDaemonServiceHandler(newDaemonService(s.cfg), opts...))
	s.mux.Handle(nokkuv1connect.NewCertificateServiceHandler(newCertificateService(s.cfg), opts...))
	s.mux.Handle(nokkuv1connect.NewInvitationServiceHandler(newInvitationService(s.cfg), opts...))
	s.mux.Handle(nokkuv1connect.NewTokenServiceHandler(newTokenService(s.cfg), opts...))
	s.mux.Handle(nokkuv1connect.NewBillingServiceHandler(newBillingService(s.cfg), opts...))
	s.mux.Handle(nokkuv1connect.NewServiceAccountServiceHandler(newServiceAccountService(s.cfg), opts...))
	s.mux.Handle(nokkuv1connect.NewAccountServiceHandler(newAccountService(s.cfg), opts...))
	s.mux.Handle(nokkuv1connect.NewAuthServiceHandler(newAuthService(s.cfg), opts...))
	s.mux.Handle(nokkuv1connect.NewSSOServiceHandler(newSSOService(s.cfg), opts...))
	s.mux.Handle(nokkuv1connect.NewSCIMServiceHandler(newSCIMService(s.cfg), opts...))
	s.mux.Handle(nokkuv1connect.NewDaemonControlServiceHandler(newDaemonControlService(s.cfg), opts...))
	s.mux.Handle(nokkuv1connect.NewRecordingServiceHandler(newRecordingService(s.cfg), opts...))

	static := web.Handler()
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// A service this build does not have, from a newer client. The SPA
		// fallback would answer it with HTML.
		if strings.HasPrefix(r.URL.Path, "/nokku.v1.") {
			http.NotFound(w, r)
			return
		}
		static.ServeHTTP(w, r)
	})

	registerAuthRoutes(s.mux, s.cfg)

	protec := newChain(s.cfg.IAM.Middleware, s.cfg.IAM.RequireLogin)
	s.mux.Handle("GET /avatars/{id}", serveAvatar(s.cfg))
	s.mux.Handle("POST /upload/avatar", protec.thenFunc(uploadAvatar(s.cfg)))
	s.mux.Handle("GET /terminal/ws", protec.thenFunc(newTerminalHandler(s.cfg).handleWebSocket))

	if s.cfg.Billing.Enabled() {
		s.mux.Handle("POST /webhooks/stripe", s.cfg.Billing.WebhookHandler())
	}

	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	if s.cfg.Debug {
		s.mux.HandleFunc("/debug/pprof/", pprof.Index)
		s.mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		s.mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		s.mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		s.mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}
}
