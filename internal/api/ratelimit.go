package api

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

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

// sensitivePaths are the HTTP auth endpoints needing tighter per-IP limits.
var sensitivePaths = map[string]struct{}{
	"/auth/register":            {},
	"/auth/login":               {},
	"/auth/login/backup-code":   {},
	"/auth/forgot-password":     {},
	"/auth/reset-password":      {},
	"/auth/resend-verification": {},
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
		ip := util.GetRemoteIP(r.Header, r.RemoteAddr)
		if _, ok := sensitivePaths[r.URL.Path]; ok {
			if !sensitiveStore.allow(ip) {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if !isAPIRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if !generalStore.allow(ip) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isAPIRoute returns true for backend endpoints. Static assets skip rate limiting.
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
