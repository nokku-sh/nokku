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
	ID   string `json:"id"`
	Name string `json:"name"`
	// PublicKey signs login certificates, HostPublicKey the host certificates daemons present.
	PublicKey     string `json:"public_key"`
	HostPublicKey string `json:"host_public_key,omitempty"`
	Default       bool   `json:"default,omitzero"`
	// The keys before the last rollover. Their certificates stay trusted until PreviousTrustedUntil.
	PreviousPublicKey     string    `json:"previous_public_key,omitempty"`
	PreviousHostPublicKey string    `json:"previous_host_public_key,omitempty"`
	PreviousTrustedUntil  time.Time `json:"previous_trusted_until,omitzero"`
}

// TrustedKeys returns the current user key and, while it is still trusted, the one it replaced.
func (ca CA) TrustedKeys() []string {
	return ca.trusted(ca.PublicKey, ca.PreviousPublicKey)
}

// TrustedHostKeys returns the current host key and, while it is still trusted, the one it replaced.
func (ca CA) TrustedHostKeys() []string {
	return ca.trusted(ca.HostPublicKey, ca.PreviousHostPublicKey)
}

func (ca CA) trusted(current, previous string) []string {
	keys := []string{strings.TrimSpace(current)}
	if prev := strings.TrimSpace(previous); prev != "" && time.Now().Before(ca.PreviousTrustedUntil) {
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
	// Until holds the usernames whose grant ends, the others are for good.
	Until map[string]time.Time `json:"until,omitempty"`
	// HostPublicKey pins the host key of a manual target.
	HostPublicKey string `json:"host_public_key,omitempty"`
}

// Manual reports whether the target has no daemon and is synced by hand.
func (t Target) Manual() bool { return t.DaemonID == "" }

// Config lives in config.json. A session belongs to the API that issued it, so both are kept together.
type Config struct {
	APIURL string `json:"api_url,omitempty"`
	// PEM of the private CA the API is trusted through, empty when the system roots know its certificate.
	APICA            string    `json:"api_ca,omitempty"`
	SessionToken     string    `json:"session_token,omitempty"`
	SessionExpiresAt time.Time `json:"session_expires_at,omitzero"`
	// TTL is kept from --ttl, ssh runs nk proxy and nk prepare without flags.
	TTL time.Duration `json:"ttl,omitzero"`
}

// Cache is the last access snapshot, kept in cache.json for offline use.
type Cache struct {
	// The API this snapshot came from. One written before this field existed has none.
	Server   string    `json:"server,omitempty"`
	SyncedAt time.Time `json:"synced_at,omitzero"`
	// FailedAt is when a sync or a renewal last failed. A sync clears it.
	FailedAt       time.Time       `json:"failed_at,omitzero"`
	User           *User           `json:"user,omitempty"`
	ServiceAccount *ServiceAccount `json:"service_account,omitempty"`
	CAs            []CA            `json:"cas,omitempty"`
	Targets        []Target        `json:"targets,omitempty"`
}

// State is in memory. Everything outside Config and Cache comes from flags and is never written to disk.
type State struct {
	Config
	Cache

	// Read from NK_TOKEN only, never argv, so it stays out of shell history and the process list.
	Token      string
	RequireTPM bool
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

// LoadCache never uses a snapshot of another server.
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

// MarkSyncFailed makes nk under ssh leave the core alone for a while, so an outage costs one attempt in total.
func (s *State) MarkSyncFailed() {
	s.FailedAt = time.Now()
	if err := fsutil.SaveJSON(paths.CacheFile(), s.Cache, 0o600); err != nil {
		slog.Debug("failed to note the core outage", "err", err)
	}
}

func (s *State) SyncFailedWithin(d time.Duration) bool {
	return time.Since(s.FailedAt) < d
}

func (s *State) IsServiceAccount() bool { return s.Token != "" }

// SubjectID is empty when the snapshot names no subject.
func (c Cache) SubjectID() string {
	switch {
	case c.User != nil:
		return "user:" + c.User.ID
	case c.ServiceAccount != nil:
		return "sa:" + c.ServiceAccount.ID
	}
	return ""
}

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
