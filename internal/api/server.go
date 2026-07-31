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

	// rootCtx is the process root context (canceled on SIGINT/SIGTERM). It is
	// set in Start and consumed by WithShutdownSignal so that long-lived
	// streaming handlers exit promptly on shutdown instead of blocking
	// http.Server.Shutdown until its deadline.
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
		slog.Info("server listening", "address", "http://127.0.0.1:"+s.cfg.Port)
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

// WithShutdownSignal derives each request's context from the request's own
// context but cancels it the moment the server's root ctx (canceled on
// SIGINT/SIGTERM) is done. This makes long-lived handlers — event subscribers,
// CLI-login streams, PTY WebSockets, bidi daemon streams — exit promptly on
// shutdown, instead of blocking [http.Server.Shutdown] until its deadline (the
// old ~3s hang on Ctrl+C). The watcher goroutine exits via ctx.Done().
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
		NewAuthNInterceptor(s.cfg),
		NewRateLimitInterceptor(),
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
					slog.Any("panic", p),
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
			Name: nokkuv1connect.AuthServiceName,
			Handler: func() (string, http.Handler) {
				return nokkuv1connect.NewAuthServiceHandler(NewAuthService(s.cfg), opts...)
			},
		},
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

	// Extract service names for health and reflection
	serviceNames := make([]string, len(registrations))
	services := make([]*vanguard.Service, len(registrations))

	for i, reg := range registrations {
		serviceNames[i] = reg.Name
		services[i] = vanguard.NewService(reg.Path, reg.Handler)
	}
	s.registerHealthAndReflection(serviceNames)

	// Initialize the Vanguard transcoder.
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

		// fallback to static files
		staticHandler.ServeHTTP(w, r)
	})

	// Use http wrapper of interceptors
	auth := NewAuthNInterceptor(s.cfg)
	audit := NewAuditInterceptor(s.cfg.Audit)

	pubChain := NewChain(audit.WithAudit)                 // Public chain (audit only, no auth)
	privChain := NewChain(audit.WithAudit, auth.WithAuth) // Private chain (audit + auth)

	// OAuth handlers (public)
	oauthHandler := NewOAuthHandler(s.cfg)
	s.mux.Handle("/oauth/login", pubChain.ThenFunc(oauthHandler.LoginHandler))
	s.mux.Handle("/oauth/callback", pubChain.ThenFunc(oauthHandler.CallbackHandler))

	// SAML handlers (public)
	samlHandler := NewSAMLHandler(s.cfg)
	s.mux.Handle("/saml/login", pubChain.ThenFunc(samlHandler.LoginHandler))
	s.mux.Handle("POST /saml/acs", pubChain.ThenFunc(samlHandler.CallbackHandler))
	s.mux.HandleFunc("/saml/metadata/{id}", samlHandler.MetadataHandler)

	// Passkey handlers
	passkeyHandler, err := NewPasskeyService(s.cfg)
	if err != nil {
		return err
	}
	s.mux.Handle(
		"POST /passkey/register/begin",
		privChain.ThenFunc(passkeyHandler.BeginRegistration),
	)
	s.mux.Handle(
		"POST /passkey/register/finish",
		privChain.ThenFunc(passkeyHandler.FinishRegistration),
	)
	s.mux.Handle("POST /passkey/login/begin", pubChain.ThenFunc(passkeyHandler.BeginLogin))
	s.mux.Handle("POST /passkey/login/finish", pubChain.ThenFunc(passkeyHandler.FinishLogin))

	// Passkey signup (public — no auth required, creates new users)
	s.mux.Handle("POST /passkey/signup/begin", pubChain.ThenFunc(passkeyHandler.BeginSignup))
	s.mux.Handle("POST /passkey/signup/finish", pubChain.ThenFunc(passkeyHandler.FinishSignup))

	// Avatar handlers
	s.mux.Handle("GET /avatars/{id}", pubChain.ThenFunc(ServeAvatar(s.cfg)))
	s.mux.Handle("POST /upload/avatar", privChain.ThenFunc(UploadAvatar(s.cfg)))

	// Terminal WebSocket: proxies browser <-> daemon's StreamSession PTY stream.
	terminal := NewTerminalHandler(s.cfg)
	s.mux.Handle("GET /terminal/ws", privChain.ThenFunc(terminal.HandleWebSocket))

	// Billing provider webhook
	if s.cfg.Billing != nil {
		s.mux.Handle("POST /webhooks/polar", s.cfg.Billing.WebhookHandler())
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

func isAPIRequest(r *http.Request) bool {
	// Check for Connect-RPC headers
	if r.Header.Get("Content-Type") == "application/json" &&
		r.Header.Get("Connect-Protocol-Version") != "" {
		return true
	}

	// Check for gRPC headers
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
