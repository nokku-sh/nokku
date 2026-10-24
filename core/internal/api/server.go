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

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
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

func (s *Server) serverInterceptors(ctx context.Context) []connect.ServerInterceptor {
	interceptors := []connect.ServerInterceptor{
		newTimeoutInterceptor(),
		newStreamEndInterceptor(ctx),
		(&authNInterceptor{cfg: s.cfg}).intercept,
		s.cfg.Audit.Intercept, // Audit wraps authorization so denied calls are recorded too.
		s.recoverRPC,          // Inside audit, so a call that panicked is recorded with its code.
		errorInterceptor,
		(&authorizationInterceptor{cfg: s.cfg}).intercept,
		entitlement.NewGuardInterceptor(s.cfg.Entitlements),
		validate.NewServerInterceptor(),
	}
	// Outermost, so it sees the mapped code and the calls turned down before the handler.
	if telemetry := newTelemetry(ctx); telemetry != nil {
		interceptors = append([]connect.ServerInterceptor{telemetry}, interceptors...)
	}
	return interceptors
}

// recoverRPC answers a panic in a handler or interceptor with an internal error, like the HTTP recover does for routes.
func (s *Server) recoverRPC(next connect.ServerFunc) connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) (err error) {
		defer func() {
			p := recover()
			if p == nil {
				return
			}
			if perr, ok := p.(error); ok && errors.Is(perr, http.ErrAbortHandler) {
				panic(p)
			}
			attrs := []slog.Attr{
				slog.String("procedure", spec.Procedure),
				slog.String("panic_type", fmt.Sprintf("%T", p)),
			}
			if s.cfg.Debug {
				attrs = append(attrs, slog.String("stack", string(debug.Stack())))
			}
			slog.LogAttrs(ctx, slog.LevelError, "rpc panic recovered", attrs...)
			err = errInternal
		}()
		return next(ctx, spec, stream)
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
	tickets := newSessionTickets()
	server := connect.NewServer(s.serverInterceptors(ctx)...)
	nokkuv1connect.RegisterWorkspaceServiceHandler(server, &workspaceService{cfg: s.cfg})
	nokkuv1connect.RegisterDashboardServiceHandler(server, &dashboardService{cfg: s.cfg})
	nokkuv1connect.RegisterTeamServiceHandler(server, &teamService{cfg: s.cfg})
	nokkuv1connect.RegisterUtilServiceHandler(server, &utilService{cfg: s.cfg})
	nokkuv1connect.RegisterTargetServiceHandler(server, &targetService{cfg: s.cfg})
	nokkuv1connect.RegisterTargetAccountServiceHandler(server, &targetAccountService{cfg: s.cfg})
	nokkuv1connect.RegisterDaemonServiceHandler(server, &daemonService{cfg: s.cfg, tickets: tickets})
	nokkuv1connect.RegisterCertificateServiceHandler(server, &certificateService{cfg: s.cfg})
	nokkuv1connect.RegisterInvitationServiceHandler(server, &invitationService{cfg: s.cfg})
	nokkuv1connect.RegisterJoinTokenServiceHandler(server, &joinTokenService{cfg: s.cfg})
	nokkuv1connect.RegisterBillingServiceHandler(server, &billingService{cfg: s.cfg})
	nokkuv1connect.RegisterServiceAccountServiceHandler(server, &serviceAccountService{cfg: s.cfg})
	nokkuv1connect.RegisterAccountServiceHandler(server, &accountService{cfg: s.cfg})
	nokkuv1connect.RegisterAuthServiceHandler(server, &authService{cfg: s.cfg})
	nokkuv1connect.RegisterSSOServiceHandler(server, &ssoService{cfg: s.cfg})
	nokkuv1connect.RegisterSCIMServiceHandler(server, &scimService{cfg: s.cfg})
	nokkuv1connect.RegisterDaemonControlServiceHandler(server, newDaemonControlService(s.cfg))
	nokkuv1connect.RegisterRecordingServiceHandler(server, &recordingService{cfg: s.cfg})
	nokkuv1connect.RegisterLegalHoldServiceHandler(server, &legalHoldService{cfg: s.cfg})
	nokkuv1connect.RegisterAccessRequestServiceHandler(server, &accessRequestService{cfg: s.cfg})
	nokkuv1connect.RegisterAuditStreamServiceHandler(server, &auditStreamService{cfg: s.cfg})
	connecthttp.Mount(s.mux, server,
		connecthttp.WithCompressMinBytes(1024),
		connecthttp.WithReadMaxBytes(maxMessageBytes),
	)

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
	s.mux.Handle("GET /avatars/{id}", protec(serveAvatar(s.cfg)))

	terminal := &terminalHandler{cfg: s.cfg, tickets: tickets}
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
