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

	"github.com/nokku-sh/nokku/internal/actor"
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

	proto := new(http.Protocols)
	proto.SetHTTP1(true)
	proto.SetHTTP2(true)
	proto.SetUnencryptedHTTP2(true)
	server := &http.Server{
		// Streams, relays and web terminals end with the root ctx, nothing else stops them.
		BaseContext:       func(net.Listener) context.Context { return ctx },
		Addr:              "0.0.0.0:" + s.cfg.Port,
		Handler:           s.handler(),
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
		newTelemetry(ctx), // Outermost, so it sees the mapped code and the calls turned down before the handler.
		newTimeoutInterceptor(),
		newAuthNInterceptor(s.cfg),
		s.cfg.Audit, // Audit wraps authorization so denied calls are recorded too.
		errorInterceptor{},
		newAuthZInterceptor(s.cfg),
		entitlement.NewGuardInterceptor(s.cfg.Entitlements),
		validate.NewInterceptor(),
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

// handler is the mux behind the middleware every request passes through.
func (s *Server) handler() http.Handler {
	return newChain(
		s.withRateLimit,
		s.withHeaders,
		s.withCSRF,
		s.withLogger,
		s.withRecover,
		s.withRequestMeta,
		s.withTenant,
	).then(s.mux)
}

// withRequestMeta puts the address and headers of the request on its
// context. Session rows and audit events take the IP and the user agent from
// there, whichever route writes them. This is the one place that sets it.
func (s *Server) withRequestMeta(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := actor.ContextWithRequestMeta(r.Context(), actor.RequestMeta{Header: r.Header, RemoteAddr: r.RemoteAddr})
		h.ServeHTTP(w, r.WithContext(ctx))
	})
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
	s.mux.Handle(nokkuv1connect.NewWorkspaceServiceHandler(&workspaceService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewDashboardServiceHandler(&dashboardService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewTeamServiceHandler(&teamService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewUtilServiceHandler(&utilService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewTargetServiceHandler(&targetService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewPrincipalServiceHandler(&principalService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewDaemonServiceHandler(&daemonService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewCertificateServiceHandler(&certificateService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewInvitationServiceHandler(&invitationService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewTokenServiceHandler(&tokenService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewBillingServiceHandler(&billingService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewServiceAccountServiceHandler(&serviceAccountService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewAccountServiceHandler(&accountService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewAuthServiceHandler(&authService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewSSOServiceHandler(&ssoService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewSCIMServiceHandler(&scimService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewDaemonControlServiceHandler(newDaemonControlService(s.cfg), opts...))
	s.mux.Handle(nokkuv1connect.NewRecordingServiceHandler(&recordingService{cfg: s.cfg}, opts...))

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
	s.mux.Handle("GET /terminal/ws", protec.thenFunc((&terminalHandler{cfg: s.cfg}).handleWebSocket))

	if s.cfg.SaaS {
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
