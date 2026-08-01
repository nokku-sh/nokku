package api

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/time/rate"

	"github.com/nokku-sh/nokku/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokku/internal/meta"
	"github.com/nokku-sh/nokku/internal/util"
)

const (
	// General per-IP rate limit (all HTTP requests including SAML, OIDC, passkeys, avatars).
	generalRPS   = 30
	generalBurst = 50

	// Sensitive auth procedures (register, login, forgot password, etc.)
	sensitiveRPS   = 5
	sensitiveBurst = 10

	cleanupInterval = 5 * time.Minute
	entryTTL        = 10 * time.Minute
)

// sensitiveProcs are ConnectRPC procedures needing tighter per-IP limits.
var sensitiveProcs = map[string]struct{}{
	nokkuv1connect.AuthServiceRegisterProcedure:            {},
	nokkuv1connect.AuthServiceLoginProcedure:               {},
	nokkuv1connect.AuthServiceLoginWithBackupCodeProcedure: {},
	nokkuv1connect.AuthServiceForgotPasswordProcedure:      {},
	nokkuv1connect.AuthServiceResetPasswordProcedure:       {},
	nokkuv1connect.AuthServiceResendVerificationProcedure:  {},
}

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type rateLimiterStore struct {
	mu      sync.Mutex
	entries map[string]*limiterEntry
	rps     int
	burst   int
}

func newRateLimiterStore(rps, burst int) *rateLimiterStore {
	s := &rateLimiterStore{
		entries: make(map[string]*limiterEntry),
		rps:     rps,
		burst:   burst,
	}
	go s.cleanup()
	return s
}

func (s *rateLimiterStore) allow(key string) bool {
	s.mu.Lock()
	e, ok := s.entries[key]
	if !ok {
		e = &limiterEntry{limiter: rate.NewLimiter(rate.Limit(s.rps), s.burst)}
		s.entries[key] = e
	}
	e.lastSeen = time.Now()
	s.mu.Unlock()
	return e.limiter.Allow()
}

func (s *rateLimiterStore) cleanup() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for key, e := range s.entries {
			if now.Sub(e.lastSeen) > entryTTL {
				delete(s.entries, key)
			}
		}
		s.mu.Unlock()
	}
}

var (
	generalStore   = newRateLimiterStore(generalRPS, generalBurst)
	sensitiveStore = newRateLimiterStore(sensitiveRPS, sensitiveBurst)
)

func (s *Server) WithRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isAPIRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		ip := util.GetRemoteIP(r.Header, r.RemoteAddr)
		if !generalStore.allow(ip) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func NewRateLimitInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if _, ok := sensitiveProcs[req.Spec().Procedure]; !ok {
				return next(ctx, req)
			}

			key := meta.UserIDFromContext(ctx)
			if key == "" {
				key = util.GetRemoteIP(req.Header(), req.Peer().Addr)
			}

			if !sensitiveStore.allow(key) {
				return nil, ErrRateLimited
			}
			return next(ctx, req)
		}
	}
}

// isAPIRoute returns true for backend endpoints; static assets skip rate limiting.
func isAPIRoute(path string) bool {
	// Streaming endpoints establish long-lived connections, rate limiting
	// their initial HTTP request would block legitimate reconnect storms.
	if strings.HasPrefix(path, "/nokku.v1.DaemonControlService/") ||
		strings.HasPrefix(path, "/nokku.v1.DaemonSessionService/") {
		return false
	}
	return strings.HasPrefix(path, "/nokku.v1.") ||
		strings.HasPrefix(path, "/grpc.") ||
		strings.HasPrefix(path, "/oauth/") ||
		strings.HasPrefix(path, "/saml/") ||
		strings.HasPrefix(path, "/passkey/") ||
		strings.HasPrefix(path, "/avatars/") ||
		strings.HasPrefix(path, "/upload/") ||
		strings.HasPrefix(path, "/terminal/") ||
		strings.HasPrefix(path, "/stripe/") ||
		strings.HasPrefix(path, "/healthz") ||
		strings.HasPrefix(path, "/debug/") ||
		strings.HasPrefix(path, "/v1/")
}
