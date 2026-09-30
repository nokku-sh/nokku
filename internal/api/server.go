// Package api contains the HTTP server for the nokku API.
package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"runtime/debug"
	"strings"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/grpchealth"
	"connectrpc.com/grpcreflect"
	"connectrpc.com/validate"
	"connectrpc.com/vanguard"
	"github.com/vearutop/statigz"

	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/entitlement"
	"github.com/nokku-sh/nokku/web"
)

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
	if err := s.registerServices(ctx); err != nil {
		return err
	}

	chain := newChain(
		s.WithRateLimit,
		s.WithHeaders,
		s.WithCORS,
		s.WithCSRF,
		s.WithLogger,
	)

	proto := new(http.Protocols)
	proto.SetHTTP1(true)
	proto.SetHTTP2(true)
	proto.SetUnencryptedHTTP2(true)
	server := &http.Server{
		// Long-lived streams exit as soon as shutdown cancels ctx.
		BaseContext:       func(net.Listener) context.Context { return ctx },
		Addr:              "0.0.0.0:" + s.cfg.Port,
		Handler:           chain.Then(s.mux),
		Protocols:         proto,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 14, // 16 KiB
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13},
	}

	serverErr := make(chan error, 1)
	go func() {
		slog.Info("server listening", "bind_address", server.Addr, "public_url", s.cfg.FullURL())
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutting down server")
		graceCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(graceCtx)

	case err := <-serverErr:
		return fmt.Errorf("server error: %w", err)
	}
}

func (s *Server) withHandlerOptions(ctx context.Context) []connect.HandlerOption {
	interceptors := []connect.Interceptor{
		NewLogInterceptor(s.cfg.Debug),
		NewTimeoutInterceptor(),
		NewAuthNInterceptor(s.cfg),
		// Audit wraps authorization so denied calls are recorded too.
		s.cfg.Audit,
		errorInterceptor{},
		NewAuthZInterceptor(s.cfg),
		entitlement.NewGuardInterceptor(s.cfg.Entitlements),
		validate.NewInterceptor(),
		NewOTLPInterceptor(ctx),
	}

	return []connect.HandlerOption{
		connect.WithCompressMinBytes(1024),
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
				return ErrInternal
			},
		),
	}
}

func (s *Server) registerServices(ctx context.Context) error {
	var names []string
	var services []*vanguard.Service
	register := func(path string, handler http.Handler) {
		names = append(names, strings.Trim(path, "/"))
		services = append(services, vanguard.NewService(path, handler))
	}
	opts := s.withHandlerOptions(ctx)
	register(nokkuv1connect.NewWorkspaceServiceHandler(NewWorkspaceService(s.cfg), opts...))
	register(nokkuv1connect.NewDashboardServiceHandler(NewDashboardService(s.cfg), opts...))
	register(nokkuv1connect.NewTeamServiceHandler(NewTeamService(s.cfg), opts...))
	register(nokkuv1connect.NewUtilServiceHandler(NewUtilService(s.cfg), opts...))
	register(nokkuv1connect.NewTargetServiceHandler(NewTargetService(s.cfg), opts...))
	register(nokkuv1connect.NewPrincipalServiceHandler(NewPrincipalService(s.cfg), opts...))
	register(nokkuv1connect.NewDaemonServiceHandler(NewDaemonService(s.cfg), opts...))
	register(nokkuv1connect.NewCertificateServiceHandler(NewCertificateService(s.cfg), opts...))
	register(nokkuv1connect.NewInvitationServiceHandler(NewInvitationService(s.cfg), opts...))
	register(nokkuv1connect.NewTokenServiceHandler(NewTokenService(s.cfg), opts...))
	register(nokkuv1connect.NewBillingServiceHandler(NewBillingService(s.cfg), opts...))
	register(nokkuv1connect.NewServiceAccountServiceHandler(NewServiceAccountService(s.cfg), opts...))
	register(nokkuv1connect.NewAccountServiceHandler(NewAccountService(s.cfg), opts...))
	register(nokkuv1connect.NewAuthServiceHandler(NewAuthService(s.cfg), opts...))
	register(nokkuv1connect.NewWorkspaceDomainServiceHandler(NewWorkspaceDomainService(s.cfg), opts...))
	register(nokkuv1connect.NewSSOServiceHandler(NewSSOService(s.cfg), opts...))
	register(nokkuv1connect.NewSCIMServiceHandler(NewSCIMService(s.cfg), opts...))
	register(nokkuv1connect.NewDaemonControlServiceHandler(s.cfg.Pool, opts...))
	register(nokkuv1connect.NewDaemonSessionServiceHandler(s.cfg.Pool, opts...))
	register(nokkuv1connect.NewRecordingServiceHandler(NewRecordingService(s.cfg), opts...))
	s.registerHealthAndReflection(names)

	transcoder, err := vanguard.NewTranscoder(services)
	if err != nil {
		return err
	}

	var staticHandler http.Handler
	staticHandler = statigz.FileServer(
		web.UIFS,
		statigz.FSPrefix("ui/build"),
		statigz.OnNotFound(func(w http.ResponseWriter, r *http.Request) {
			// A build without the UI has no index.html to fall back to.
			if r.URL.Path == "/" {
				http.NotFound(w, r)
				return
			}
			r.URL.Path = "/" // SPA fallback to index.html
			staticHandler.ServeHTTP(w, r)
		}),
	)

	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if isAPIRequest(r) {
			transcoder.ServeHTTP(w, r)
			return
		}

		staticHandler.ServeHTTP(w, r)
	})

	registerAuthRoutes(s.mux, s.cfg)

	protec := newChain(s.cfg.IAM.Middleware, s.cfg.IAM.RequireLogin)
	s.mux.Handle("GET /avatars/{id}", ServeAvatar(s.cfg))
	s.mux.Handle("POST /upload/avatar", protec.ThenFunc(UploadAvatar(s.cfg)))
	s.mux.Handle("GET /terminal/ws", protec.ThenFunc(NewTerminalHandler(s.cfg).HandleWebSocket))

	if s.cfg.Billing.Enabled() {
		s.mux.Handle("POST /webhooks/stripe", s.cfg.Billing.WebhookHandler())
	}

	if s.cfg.Debug {
		s.mux.HandleFunc("/debug/pprof/", pprof.Index)
		s.mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		s.mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		s.mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		s.mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}
	return nil
}

func (s *Server) registerHealthAndReflection(serviceNames []string) {
	checker := grpchealth.NewStaticChecker(serviceNames...)
	reflector := grpcreflect.NewStaticReflector(serviceNames...)

	s.mux.Handle(grpchealth.NewHandler(checker))
	s.mux.Handle(grpcreflect.NewHandlerV1(reflector))
	s.mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func isAPIRequest(r *http.Request) bool {
	if r.Header.Get("Content-Type") == "application/json" &&
		r.Header.Get("Connect-Protocol-Version") != "" {
		return true
	}

	if contentType := r.Header.Get("Content-Type"); contentType == "application/grpc" ||
		contentType == "application/grpc+proto" {
		return true
	}

	return strings.HasPrefix(r.URL.Path, "/nokku.v1.") || strings.HasPrefix(r.URL.Path, "/v1/")
}
