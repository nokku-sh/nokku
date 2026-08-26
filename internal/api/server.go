// Package api contains the HTTP server for the nokku API
package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
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

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokku/web"
)

type Server struct {
	mux *http.ServeMux
	cfg *config.Config

	// Process root context, canceled on SIGINT/SIGTERM. Consumed by
	// WithShutdownSignal so long-lived streams exit before Shutdown's deadline.
	rootCtx context.Context
}

type ServiceRegistration struct {
	Name    string
	Path    string
	Handler http.Handler
}

func New(cfg *config.Config) *Server {
	return &Server{
		mux: http.NewServeMux(),
		cfg: cfg,
	}
}

func (s *Server) Start(ctx context.Context) error {
	s.rootCtx = ctx

	if err := s.registerServices(ctx); err != nil {
		return err
	}

	chain := NewChain(
		s.WithShutdownSignal,
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
		if err := server.Shutdown(graceCtx); err != nil {
			return err
		}
		return nil

	case err := <-serverErr:
		return fmt.Errorf("server error: %w", err)
	}
}

// WithShutdownSignal cancels each request's context when the root ctx
// (SIGINT/SIGTERM) is done.
func (s *Server) WithShutdownSignal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		root := s.rootCtx
		if root == nil {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		go func() {
			select {
			case <-ctx.Done():
			case <-root.Done():
				cancel()
			}
		}()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) withHandlerOptions(ctx context.Context) []connect.HandlerOption {
	interceptors := []connect.Interceptor{
		NewLogInterceptor(s.cfg.Debug),
		NewTimeoutInterceptor(),
		NewKagiAuthNInterceptor(s.cfg),
		NewAuthZInterceptor(s.cfg),
		NewAuditInterceptor(s.cfg.Audit),
		validate.NewInterceptor(),
	}
	if otel := NewOTLPInterceptor(ctx); otel != nil {
		interceptors = append(interceptors, otel)
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

func (s *Server) getServiceRegistrations(ctx context.Context) []ServiceRegistration {
	opts := s.withHandlerOptions(ctx)
	services := []struct {
		Name    string
		Handler func() (string, http.Handler)
	}{
		{
			Name: nokkuv1connect.UserServiceName,
			Handler: func() (string, http.Handler) {
				return nokkuv1connect.NewUserServiceHandler(NewUserService(s.cfg), opts...)
			},
		},
		{
			Name: nokkuv1connect.CredentialServiceName,
			Handler: func() (string, http.Handler) {
				return nokkuv1connect.NewCredentialServiceHandler(
					NewCredentialService(s.cfg),
					opts...,
				)
			},
		},
		{
			Name: nokkuv1connect.WorkspaceServiceName,
			Handler: func() (string, http.Handler) {
				return nokkuv1connect.NewWorkspaceServiceHandler(
					NewWorkspaceService(s.cfg),
					opts...,
				)
			},
		},
		{
			Name: nokkuv1connect.TeamServiceName,
			Handler: func() (string, http.Handler) {
				return nokkuv1connect.NewTeamServiceHandler(NewTeamService(s.cfg), opts...)
			},
		},
		{
			Name: nokkuv1connect.UtilServiceName,
			Handler: func() (string, http.Handler) {
				return nokkuv1connect.NewUtilServiceHandler(NewUtilService(s.cfg), opts...)
			},
		},
		{
			Name: nokkuv1connect.TargetServiceName,
			Handler: func() (string, http.Handler) {
				return nokkuv1connect.NewTargetServiceHandler(NewTargetService(s.cfg), opts...)
			},
		},
		{
			Name: nokkuv1connect.PrincipalServiceName,
			Handler: func() (string, http.Handler) {
				return nokkuv1connect.NewPrincipalServiceHandler(
					NewPrincipalService(s.cfg),
					opts...,
				)
			},
		},
		{
			Name: nokkuv1connect.DaemonServiceName,
			Handler: func() (string, http.Handler) {
				return nokkuv1connect.NewDaemonServiceHandler(NewDaemonService(s.cfg), opts...)
			},
		},
		{
			Name: nokkuv1connect.CertificateServiceName,
			Handler: func() (string, http.Handler) {
				return nokkuv1connect.NewCertificateServiceHandler(
					NewCertificateService(s.cfg),
					opts...,
				)
			},
		},
		{
			Name: nokkuv1connect.InvitationServiceName,
			Handler: func() (string, http.Handler) {
				return nokkuv1connect.NewInvitationServiceHandler(
					NewInvitationService(s.cfg),
					opts...,
				)
			},
		},
		{
			Name: nokkuv1connect.BillingServiceName,
			Handler: func() (string, http.Handler) {
				return nokkuv1connect.NewBillingServiceHandler(NewBillingService(s.cfg), opts...)
			},
		},
		{
			Name: nokkuv1connect.LicenseServiceName,
			Handler: func() (string, http.Handler) {
				return nokkuv1connect.NewLicenseServiceHandler(NewLicenseService(s.cfg), opts...)
			},
		},
		{
			Name: nokkuv1connect.ServiceAccountServiceName,
			Handler: func() (string, http.Handler) {
				return nokkuv1connect.NewServiceAccountServiceHandler(
					NewServiceAccountService(s.cfg),
					opts...,
				)
			},
		},
		{
			Name: nokkuv1connect.WorkspaceDomainServiceName,
			Handler: func() (string, http.Handler) {
				return nokkuv1connect.NewWorkspaceDomainServiceHandler(
					NewWorkspaceDomainService(s.cfg),
					opts...,
				)
			},
		},
		{
			Name: nokkuv1connect.SSOServiceName,
			Handler: func() (string, http.Handler) {
				return nokkuv1connect.NewSSOServiceHandler(NewSSOService(s.cfg), opts...)
			},
		},
		{
			Name: nokkuv1connect.DaemonControlServiceName,
			Handler: func() (string, http.Handler) {
				return nokkuv1connect.NewDaemonControlServiceHandler(s.cfg.Pool, opts...)
			},
		},
		{
			Name: nokkuv1connect.DaemonSessionServiceName,
			Handler: func() (string, http.Handler) {
				return nokkuv1connect.NewDaemonSessionServiceHandler(s.cfg.Pool, opts...)
			},
		},
		{
			Name: nokkuv1connect.RecordingServiceName,
			Handler: func() (string, http.Handler) {
				return nokkuv1connect.NewRecordingServiceHandler(
					NewRecordingService(s.cfg),
					opts...)
			},
		},
	}

	registrations := make([]ServiceRegistration, 0, len(services))
	for _, svc := range services {
		path, handler := svc.Handler()
		registrations = append(registrations, ServiceRegistration{
			Name:    svc.Name,
			Path:    path,
			Handler: handler,
		})
	}
	return registrations
}

func (s *Server) registerServices(ctx context.Context) error {
	registrations := s.getServiceRegistrations(ctx)

	serviceNames := make([]string, len(registrations))
	services := make([]*vanguard.Service, len(registrations))

	for i, reg := range registrations {
		serviceNames[i] = reg.Name
		services[i] = vanguard.NewService(reg.Path, reg.Handler)
	}
	s.registerHealthAndReflection(serviceNames)

	transcoder, err := vanguard.NewTranscoder(services)
	if err != nil {
		return err
	}

	var staticHandler http.Handler
	staticHandler = statigz.FileServer(
		web.UIFS,
		statigz.FSPrefix("ui/build"),
		statigz.OnNotFound(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Path = "/" // Serve index.html for SPA routing
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

	audit := NewAuditInterceptor(s.cfg.Audit)

	// Consolidated kagi auth handler: SSO, passkey, device, and the
	// credential/email flows, mounted at their existing public paths. The
	// handler's own paths are prefix-free, so each route is re-prefixed
	// with its public location (/auth for the credential and device flows,
	// none for SSO and passkeys).
	authHandler, err := NewAuthHandler(s.cfg)
	if err != nil {
		return err
	}
	for _, route := range authHandler.Routes() {
		method, path, ok := strings.Cut(route.Pattern, " ")
		if !ok {
			continue
		}
		// No access-log audit wrapper here: kagi records semantic events
		// (login_success, login_denied, logout, ...) through the sink, one
		// row per flow instead of two.
		s.mux.Handle(method+" "+authRoutePrefix(path)+path, route.Handler)
	}

	// Auth outside audit, matching the RPC interceptor order, so audited
	// rows see the principal and tenant kagi placed on the request.
	pubChain := NewChain(audit.WithAudit)                      // Public chain (audit only, no auth)
	privChain := NewChain(NewHTTPAuth(s.cfg), audit.WithAudit) // Private chain (auth + audit)

	// Avatar handlers
	s.mux.Handle("GET /avatars/{id}", pubChain.ThenFunc(ServeAvatar(s.cfg)))
	s.mux.Handle("POST /upload/avatar", privChain.ThenFunc(UploadAvatar(s.cfg)))

	// Terminal WebSocket: proxies browser <-> daemon's StreamSession PTY stream.
	terminal := NewTerminalHandler(s.cfg)
	s.mux.Handle("GET /terminal/ws", privChain.ThenFunc(terminal.HandleWebSocket))

	// Billing provider webhook
	if s.cfg.Billing.Enabled() {
		s.mux.Handle("POST /webhooks/stripe", s.cfg.Billing.WebhookHandler())
	}

	// Debug
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

// authRoutePrefix returns the public prefix a kagi auth route mounts under:
// the credential, email, and device flows live under /auth; the SSO and
// passkey surfaces are mounted at the root.
func authRoutePrefix(path string) string {
	switch {
	case strings.HasPrefix(path, "/oidc"),
		strings.HasPrefix(path, "/oauth"),
		strings.HasPrefix(path, "/saml"),
		strings.HasPrefix(path, "/passkey"):
		return ""
	default:
		return "/auth"
	}
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

	path := r.URL.Path
	if strings.HasPrefix(path, "/nokku.v1.") {
		return true
	}

	apiPrefixes := []string{"/v1/"}

	for _, prefix := range apiPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
