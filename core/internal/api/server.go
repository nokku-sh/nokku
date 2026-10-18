package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/validate"

	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
	"github.com/nokku-sh/nokku/core/internal/webpki"
	"github.com/nokku-sh/nokku/core/web"
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
	if s.cfg.SaaS {
		go runLifecycle(ctx, s.cfg)
	}

	proto := new(http.Protocols)
	proto.SetHTTP1(true)
	proto.SetHTTP2(true)
	proto.SetUnencryptedHTTP2(true)

	// Requests outlive the root ctx by the shutdown grace. Streams, relays and web terminals end with it.
	base, stop := context.WithCancel(context.WithoutCancel(ctx))
	defer stop()
	server := &http.Server{
		BaseContext:       func(net.Listener) context.Context { return base },
		Addr:              "0.0.0.0:" + s.cfg.Port,
		Handler:           s.Handler(ctx),
		Protocols:         proto,
		ErrorLog:          slog.NewLogLogger(quietHandshakes{slog.Default().Handler()}, slog.LevelInfo),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 14, // 16 KiB
	}
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", server.Addr)
	if err != nil {
		return fmt.Errorf("server error: %w", err)
	}

	serverErr := make(chan error, 1)
	go func() {
		slog.Info("server listening", "bind_address", server.Addr, "public_url", s.cfg.FullURL())
		if s.cfg.BootstrapLink != "" {
			slog.Warn("the owner has no passkey yet, sign in with this link, it works for 24 hours",
				"url", s.cfg.BootstrapLink)
		}
		// One port: TLS for a client that connects by itself, plain HTTP for a proxy.
		err := server.Serve(s.cfg.WebPKI.Listener(listener))
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case <-ctx.Done():
		graceCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := server.Shutdown(graceCtx)
		if errors.Is(err, context.DeadlineExceeded) {
			slog.Warn("shutdown grace ran out, cutting the requests still open")
			return nil
		}
		return err

	case err := <-serverErr:
		return fmt.Errorf("server error: %w", err)
	}
}

func (s *Server) withHandlerOptions(ctx context.Context) []connect.HandlerOption {
	interceptors := []connect.Interceptor{
		newTelemetry(ctx), // Outermost, so it sees the mapped code and the calls turned down before the handler.
		newTimeoutInterceptor(),
		newStreamEndInterceptor(ctx),
		&authNInterceptor{cfg: s.cfg},
		s.cfg.Audit, // Audit wraps authorization so denied calls are recorded too.
		errorInterceptor{},
		&authorizationInterceptor{cfg: s.cfg},
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
	return chain(
		s.withHTTPS,
		s.withRateLimit,
		s.withHeaders,
		s.withCSRF,
		s.withLogger,
		s.withRecover,
		s.withRequestMeta,
		s.withTenant,
	)(s.mux.ServeHTTP)
}

// withRequestMeta is the one place that sets the address and headers session rows and audit events read.
func (s *Server) withRequestMeta(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta := actor.RequestMeta{Header: r.Header, RemoteAddr: r.RemoteAddr, TLS: r.TLS != nil}
		ctx := actor.ContextWithRequestMeta(r.Context(), meta)
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
	s.mux.Handle(nokkuv1connect.NewLegalHoldServiceHandler(&legalHoldService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewAccessRequestServiceHandler(&accessRequestService{cfg: s.cfg}, opts...))
	s.mux.Handle(nokkuv1connect.NewAuditStreamServiceHandler(&auditStreamService{cfg: s.cfg}, opts...))

	static := web.Handler()
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

	protec := chain(s.cfg.IAM.Middleware, s.cfg.IAM.RequireLogin)
	s.mux.Handle("GET /avatars/{id}", serveAvatar(s.cfg))
	s.mux.Handle("POST /upload/avatar", protec(uploadAvatar(s.cfg)))

	terminal := &terminalHandler{cfg: s.cfg}
	s.mux.Handle("GET /terminal/ws", protec(func(w http.ResponseWriter, r *http.Request) {
		// A terminal is a stream, it ends with the root ctx like the RPC ones.
		rctx, release := endWith(r.Context(), ctx)
		defer release()
		terminal.handleWebSocket(w, r.WithContext(rctx))
	}))

	if s.cfg.SaaS {
		s.mux.Handle("POST /webhooks/stripe", s.cfg.Billing.WebhookHandler())
	}

	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}
