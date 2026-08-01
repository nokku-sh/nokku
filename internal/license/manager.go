package license

import (
	"context"
	"sync"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config holds the instance license configuration.
type Config struct {
	Key string `env:"NOKKU_LICENSE_KEY"`
}

// Manager holds the validated state of the instance license key. An empty key
// means the instance is not licensed; validation is offline.
type Manager struct {
	mu       sync.RWMutex
	verifier *Verifier
	key      string
	current  *Key
}

func NewManager() (*Manager, error) {
	cfg, err := env.ParseAs[Config]()
	if err != nil {
		return nil, err
	}
	verifier, err := DefaultVerifier()
	if err != nil {
		return nil, err
	}
	return &Manager{verifier: verifier, key: cfg.Key}, nil
}

// Validate verifies the configured key and stores the result. Idempotent.
func (m *Manager) Validate(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.key == "" {
		m.current = nil
		return nil
	}
	validated, err := m.verifier.Verify(m.key)
	if validated != nil {
		m.current = validated
	} else {
		m.current = nil
	}
	return err
}

// Configured reports whether a license key is set at all.
func (m *Manager) Configured() bool {
	return m.key != ""
}

// Active reports whether a valid, unexpired key is configured. Expiry is
// evaluated per call, so a key that lapses mid-run stops granting access.
func (m *Manager) Active() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current != nil && m.current.Valid()
}

// Key returns the configured license key, or "" when none is set.
func (m *Manager) Key() string {
	return m.key
}

// ExpiresAt returns the validated key expiry, or nil when unknown.
func (m *Manager) ExpiresAt() *time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.current == nil {
		return nil
	}
	return m.current.ExpiresAt
}

var _ State = (*Manager)(nil)
