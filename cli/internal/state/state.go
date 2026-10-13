// Package state holds the persisted session and the offline access snapshot.
package state

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/mizuchilabs/kata/fsutil"

	"github.com/nokku-sh/nokku/cli/internal/paths"
)

type User struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type ServiceAccount struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type CA struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Default   bool   `json:"default,omitzero"`
	// RotatedAt is when the current key was issued.
	RotatedAt time.Time `json:"rotated_at,omitzero"`
	// PreviousPublicKey is the key before the last rollover. Its certificates
	// stay trusted until PreviousTrustedUntil.
	PreviousPublicKey    string    `json:"previous_public_key,omitempty"`
	PreviousTrustedUntil time.Time `json:"previous_trusted_until,omitzero"`
}

// TrustedKeys returns the current key and, while it is still trusted, the one
// it replaced.
func (ca CA) TrustedKeys() []string {
	keys := []string{strings.TrimSpace(ca.PublicKey)}
	if prev := strings.TrimSpace(ca.PreviousPublicKey); prev != "" && time.Now().Before(ca.PreviousTrustedUntil) {
		keys = append(keys, prev)
	}
	return keys
}

type Target struct {
	ID        string   `json:"id"`
	CAID      string   `json:"ca_id,omitempty"`
	DaemonID  string   `json:"daemon_id,omitempty"`
	Name      string   `json:"name"`
	Endpoints []string `json:"endpoints,omitempty"`
	// Usernames are the accounts this subject may log in as on the target.
	Usernames []string `json:"usernames,omitempty"`
	// HostPublicKey pins the host key of a manual target.
	HostPublicKey string            `json:"host_public_key,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// Manual reports whether the target has no daemon and is synced by hand.
func (t Target) Manual() bool { return t.DaemonID == "" }

// NeedsSync reports whether the server of a manual target has not seen the
// current key of ca yet. Certificates signed by that key are rejected there.
func (t Target) NeedsSync(ca *CA) bool {
	return t.Manual() && ca != nil && ca.RotatedAt.After(t.LastManualSync())
}

// LastManualSync is when an operator last ran nk sync, zero when never.
func (t Target) LastManualSync() time.Time {
	ts, _ := time.Parse(time.RFC3339, t.Metadata["last_manual_sync"])
	return ts
}

// Config is persisted in config.json. A session belongs to the API that issued
// it, so both live together.
type Config struct {
	APIURL string `json:"api_url,omitempty"`
	// APICA is the PEM of the private CA the API is trusted through, empty
	// when the system roots know its certificate.
	APICA string `json:"api_ca,omitempty"`
	// APICAInstalled is set once nk put that CA into the system trust store,
	// so the sign-out knows there is something to take out again.
	APICAInstalled   bool      `json:"api_ca_installed,omitzero"`
	SessionToken     string    `json:"session_token,omitempty"`
	SessionExpiresAt time.Time `json:"session_expires_at,omitzero"`
}

// Cache is the last access snapshot, persisted in cache.json for offline use.
type Cache struct {
	// Server is the API this snapshot came from. One written before this
	// field existed has none.
	Server   string    `json:"server,omitempty"`
	SyncedAt time.Time `json:"synced_at,omitzero"`
	// FailedAt is when a sync or a renewal last failed. A sync clears it.
	FailedAt       time.Time       `json:"failed_at,omitzero"`
	User           *User           `json:"user,omitempty"`
	ServiceAccount *ServiceAccount `json:"service_account,omitempty"`
	CAs            []CA            `json:"cas,omitempty"`
	Targets        []Target        `json:"targets,omitempty"`
}

// State is the in-memory session. Everything outside Config and Cache comes
// from flags and is never written to disk.
type State struct {
	Config
	Cache

	// Token is a service account token. It is read from NK_TOKEN only, never
	// argv, so it stays out of shell history and the process list.
	Token      string
	TTL        time.Duration
	RequireTPM bool
	// Pin names the private CA of the API, see internal/trust.
	Pin string
}

// Load reads config and cache. A missing or corrupt file starts empty.
func Load() *State {
	s := &State{}
	if err := fsutil.LoadJSON(paths.ConfigFile(), &s.Config); err != nil {
		slog.Warn("failed to load config", "err", err)
	}
	if err := s.LoadCache(); err != nil {
		slog.Warn("failed to load cache", "err", err)
	}
	return s
}

// LoadCache replaces the in-memory snapshot with the one on disk. A snapshot
// of another server is never used.
func (s *State) LoadCache() error {
	s.Cache = Cache{}
	if err := fsutil.LoadJSON(paths.CacheFile(), &s.Cache); err != nil {
		return err
	}
	if s.Server != "" && s.Server != s.APIURL {
		s.Cache = Cache{}
	}
	return nil
}

func (s *State) Save() error {
	if err := fsutil.SaveJSON(paths.ConfigFile(), s.Config, 0o600); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}
	if err := fsutil.SaveJSON(paths.CacheFile(), s.Cache, 0o600); err != nil {
		return fmt.Errorf("saving cache: %w", err)
	}
	return nil
}

// MarkSyncFailed notes that a sync or a renewal failed just now, because the
// backend was out of reach or the session ran out. nk under ssh then leaves
// it alone for a while, so that costs one attempt and not one per connection.
func (s *State) MarkSyncFailed() {
	s.FailedAt = time.Now()
	if err := fsutil.SaveJSON(paths.CacheFile(), s.Cache, 0o600); err != nil {
		slog.Debug("failed to note the backend outage", "err", err)
	}
}

// SyncFailedWithin reports whether a sync or a renewal failed within d.
func (s *State) SyncFailedWithin(d time.Duration) bool {
	return time.Since(s.FailedAt) < d
}

// IsServiceAccount reports whether a service account token is in use.
func (s *State) IsServiceAccount() bool { return s.Token != "" }

func (s *State) SessionValid() bool {
	if s.IsServiceAccount() {
		return true
	}
	if s.SessionToken == "" {
		return false
	}
	return s.SessionExpiresAt.IsZero() || time.Now().Before(s.SessionExpiresAt)
}

func (s *State) HasCachedData() bool {
	return len(s.Targets) > 0 && (s.User != nil || s.ServiceAccount != nil)
}

func (s *State) TargetByID(id string) *Target {
	for i := range s.Targets {
		if s.Targets[i].ID == id {
			return &s.Targets[i]
		}
	}
	return nil
}

func (s *State) CAByID(id string) *CA {
	for i := range s.CAs {
		if s.CAs[i].ID == id {
			return &s.CAs[i]
		}
	}
	return nil
}
