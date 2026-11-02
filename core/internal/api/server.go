package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"connectrpc.com/validate"

	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/cache"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/egress"
	"github.com/nokku-sh/nokku/core/web"
)

// The largest real messages are 32 KiB recording chunks and relay frames.
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
		// Not in config.New, the hosted tests boot through it on loopback.
		if err := egress.CheckHosted(); err != nil {
			return err
		}
		go runLifecycle(ctx, s.cfg)
	}

	proto := new(http.Protocols)
	proto.SetHTTP1(true)
	proto.SetHTTP2(true)
	proto.SetUnencryptedHTTP2(true)

	// Requests outlive ctx by the grace. Streams and terminals end with it.
	base, stop := context.WithCancel(context.WithoutCancel(ctx))
	defer stop()
	server := &http.Server{
		BaseContext:       func(net.Listener) context.Context { return base },
		Addr:              "0.0.0.0:" + s.cfg.Port,
		Handler:           s.Handler(ctx),
		Protocols:         proto,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 14,
	}
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", server.Addr)
	if err != nil {
		return fmt.Errorf("server error: %w", err)
	}

	serverErr := make(chan error, 1)
	go func() {
		slog.Info("server listening", "bind_address", server.Addr, "public_url", s.cfg.FullURL())
		if s.cfg.OwnerNeedsLink {
			slog.Warn("the owner has no passkey yet, run nokku admin-link for a sign-in link")
			s.printOwnerLink(ctx)
		}
		err := server.Serve(listener)
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

// Handler registers every route, so call it once per Server.
func (s *Server) Handler(ctx context.Context) http.Handler {
	s.registerServices(ctx)
	return s.handler()
}

func (s *Server) handler() http.Handler {
	return chain(
		s.withTrace,
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

// printOwnerLink writes to a terminal only, a log line can reach telemetry.
func (s *Server) printOwnerLink(ctx context.Context) {
	if fi, err := os.Stderr.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return
	}
	owner, link, err := s.cfg.IAM.AdminLink(ctx, s.cfg.Tenant.Single())
	if err != nil {
		slog.Error("failed to issue the owner's sign-in link", "error", err)
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "\nSign in as %s within 24 hours:\n\n  %s\n\n", owner.Email, link)
}

// withRequestMeta sets the address and headers that sessions and audit read.
func (s *Server) withRequestMeta(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta := actor.RequestMeta{Header: r.Header, RemoteAddr: r.RemoteAddr}
		ctx := actor.ContextWithRequestMeta(r.Context(), meta)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// withTenant skips /healthz and webhooks, they have no workspace host.
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
	tickets := cache.New[string, sessionTicket](sessionTicketEntries, sessionTicketTTL)
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
	nokkuv1connect.RegisterAccessRequestServiceHandler(server, &accessRequestService{cfg: s.cfg})
	nokkuv1connect.RegisterAuditStreamServiceHandler(server, &auditStreamService{cfg: s.cfg})
	connecthttp.Mount(s.mux, server,
		connecthttp.WithCompressMinBytes(1024),
		connecthttp.WithReadMaxBytes(maxMessageBytes),
	)

	static := web.Handler()
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// A newer client's service, the SPA fallback would answer it in HTML.
		if strings.HasPrefix(r.URL.Path, "/nokku.v1.") {
			http.NotFound(w, r)
			return
		}
		static.ServeHTTP(w, r)
	})

	registerAuthRoutes(s.mux, s.cfg)

	protec := chain(s.cfg.IAM.Middleware, s.cfg.IAM.RequireLogin)

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

func (s *Server) serverInterceptors(ctx context.Context) []connect.ServerInterceptor {
	interceptors := []connect.ServerInterceptor{
		newTimeoutInterceptor(),
		newStreamEndInterceptor(ctx),
		(&authNInterceptor{cfg: s.cfg}).intercept,
		// Audit wraps authorization, so denied calls are recorded too.
		s.cfg.Audit.Intercept,
		// Inside audit, so a panicked call is recorded with its code.
		s.recoverRPC,
		errorInterceptor,
		(&authorizationInterceptor{cfg: s.cfg}).intercept,
		validate.NewServerInterceptor(),
	}
	// Outermost, so it sees the mapped code and the calls turned down early.
	if telemetry := newTelemetry(ctx); telemetry != nil {
		interceptors = append([]connect.ServerInterceptor{telemetry}, interceptors...)
	}
	return interceptors
}
