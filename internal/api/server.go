package api

import (
	"context"
	"errors"
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
	"github.com/nokku-sh/nokku/internal/webpki"
	"github.com/nokku-sh/nokku/web"
)

// maxMessageBytes bounds one Connect message. The largest real ones are 32 KiB recording chunks and relay frames.
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
	proto := new(http.Protocols)
	proto.SetHTTP1(true)
	proto.SetHTTP2(true)
	tlsConf := s.cfg.WebPKI.TLSConfig()
	proto.SetUnencryptedHTTP2(tlsConf == nil)
	server := &http.Server{
		// Streams, relays and web terminals end with the root ctx, nothing else stops them.
		BaseContext:       func(net.Listener) context.Context { return ctx },
		Addr:              "0.0.0.0:" + s.cfg.Port,
		Handler:           s.Handler(ctx),
		Protocols:         proto,
		TLSConfig:         tlsConf,
		ErrorLog:          slog.NewLogLogger(quietHandshakes{slog.Default().Handler()}, slog.LevelInfo),
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
		if s.cfg.UIDev.Host != "" {
			slog.Warn("the UI comes from the Vite dev server and its scripts are not pinned, this is for development",
				"dev_server", s.cfg.UIDev.String())
		}
		if pin := s.cfg.WebPKI.Pin(); pin != "" {
			slog.Info("a private CA is advertised, nk and nokkud keep it once it matches the pin",
				"pin", pin, "ca", s.cfg.FullURL()+webpki.Path)
		}
		listen := server.ListenAndServe
		if tlsConf != nil {
			listen = func() error { return server.ListenAndServeTLS("", "") }
		}
		if err := listen(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

// Handler registers every route. Call it once per Server, the mux takes a route only once.
func (s *Server) Handler(ctx context.Context) http.Handler {
	s.registerServices(ctx)
	return s.handler()
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

// withRequestMeta is the one place that sets the address and headers session rows and audit events read.
func (s *Server) withRequestMeta(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := actor.ContextWithRequestMeta(r.Context(), actor.RequestMeta{Header: r.Header, RemoteAddr: r.RemoteAddr})
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// withTenant skips the health check and provider webhooks, they are not tied to a workspace host.
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
	s.mux.Handle(nokkuv1connect.NewTargetAccountServiceHandler(&targetAccountService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewDaemonServiceHandler(&daemonService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewCertificateServiceHandler(&certificateService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewInvitationServiceHandler(&invitationService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewJoinTokenServiceHandler(&joinTokenService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewBillingServiceHandler(&billingService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewServiceAccountServiceHandler(&serviceAccountService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewAccountServiceHandler(&accountService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewAuthServiceHandler(&authService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewSSOServiceHandler(&ssoService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewSCIMServiceHandler(&scimService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewDaemonControlServiceHandler(newDaemonControlService(s.cfg), opts...))
	s.mux.Handle(nokkuv1connect.NewRecordingServiceHandler(&recordingService{cfg: s.cfg}, opts...))

	static := web.Handler(&s.cfg.UIDev)
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// A service this build does not have, from a newer client. The SPA fallback would answer it with HTML.
		if strings.HasPrefix(r.URL.Path, "/nokku.v1.") {
			http.NotFound(w, r)
			return
		}
		static.ServeHTTP(w, r)
	})

	registerAuthRoutes(s.mux, s.cfg)
	// Public, a client reads it before it trusts the certificate.
	s.mux.Handle("GET "+webpki.Path, s.cfg.WebPKI)

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
