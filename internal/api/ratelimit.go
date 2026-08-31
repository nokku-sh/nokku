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
	// General per-IP rate limit (all HTTP requests including SAML, OIDC, avatars).
	generalRPS   = 30
	generalBurst = 50

	// Auth endpoints get a stricter per-IP limit: they are the brute-force
	// and enumeration surface (login, register, the mail round trips, SSO
	// start, device polling).
	authRPS   = 5
	authBurst = 10

	cleanupInterval = 5 * time.Minute
	entryTTL        = 10 * time.Minute
)

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

var generalStore = newRateLimiterStore(generalRPS, generalBurst)

var authStore = newRateLimiterStore(authRPS, authBurst)

func (s *Server) WithRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := util.GetRemoteIP(r.Header, r.RemoteAddr)
		if !isAPIRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		store := generalStore
		if isAuthRoute(r.URL.Path) {
			store = authStore
		}
		if !store.allow(ip) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isAuthRoute returns true for the browser-facing auth surface, which gets
// the stricter per-IP limit: the JSON API under /auth plus the SSO flow
// redirects at the root.
func isAuthRoute(path string) bool {
	return strings.HasPrefix(path, "/auth/") ||
		strings.HasPrefix(path, "/oidc/") ||
		strings.HasPrefix(path, "/oauth/") ||
		strings.HasPrefix(path, "/saml/") ||
		strings.HasPrefix(path, "/passkey/")
}

// isAPIRoute returns true for backend endpoints. Static assets skip rate limiting.
func isAPIRoute(path string) bool {
	// Streaming endpoints establish long-lived connections, rate limiting
	// their initial HTTP request would block legitimate reconnect storms.
	if strings.HasPrefix(path, "/nokku.v1.DaemonControlService/") ||
		strings.HasPrefix(path, "/nokku.v1.DaemonSessionService/") {
		return false
	}
	return strings.HasPrefix(path, "/auth/") ||
		strings.HasPrefix(path, "/nokku.v1.") ||
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
