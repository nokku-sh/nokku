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
	// PublicKey signs logins, HostPublicKey the host certificates of daemons.
	PublicKey     string `json:"public_key"`
	HostPublicKey string `json:"host_public_key,omitempty"`
	// The keys before the last rollover, trusted until PreviousTrustedUntil.
	PreviousPublicKey     string    `json:"previous_public_key,omitempty"`
	PreviousHostPublicKey string    `json:"previous_host_public_key,omitempty"`
	PreviousTrustedUntil  time.Time `json:"previous_trusted_until,omitzero"`
}

type Target struct {
	ID        string   `json:"id"`
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

// Config keeps a session with the API that issued it.
type Config struct {
	APIURL string `json:"api_url,omitempty"`
	// PEM of the API's private CA, empty when the system roots know it.
	APICA            string    `json:"api_ca,omitempty"`
	SessionToken     string    `json:"session_token,omitempty"`
	SessionExpiresAt time.Time `json:"session_expires_at,omitzero"`
	// TTL is kept from --ttl, ssh runs nk proxy and nk prepare without flags.
	TTL time.Duration `json:"ttl,omitzero"`
}

// Cache is the last access snapshot, kept in cache.json for offline use.
type Cache struct {
	// Server is empty in a snapshot older than this field.
	Server   string    `json:"server,omitempty"`
	SyncedAt time.Time `json:"synced_at,omitzero"`
	// FailedAt is when a sync or a renewal last failed. A sync clears it.
	FailedAt       time.Time       `json:"failed_at,omitzero"`
	User           *User           `json:"user,omitempty"`
	ServiceAccount *ServiceAccount `json:"service_account,omitempty"`
	CA             *CA             `json:"ca,omitempty"`
	Targets        []Target        `json:"targets,omitempty"`
}

// State outside Config and Cache is never written to disk.
type State struct {
	Config
	Cache

	// NK_TOKEN only, never argv, so it stays out of history and process lists.
	Token      string
	RequireTPM bool
}

// TrustedKeys is the user key and, while still trusted, the one it replaced.
func (ca CA) TrustedKeys() []string {
	return ca.trusted(ca.PublicKey, ca.PreviousPublicKey)
}

// TrustedHostKeys is [CA.TrustedKeys] for the host key.
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

func (t Target) Manual() bool { return t.DaemonID == "" }

// Load starts empty on a missing or corrupt file.
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

// MarkSyncFailed backs nk off the core, so an outage costs one attempt.
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

// CIJob is an nk login --ci session. An NK_TOKEN snapshot has no session.
func (s *State) CIJob() bool { return s.Token == "" && s.ServiceAccount != nil && s.SessionToken != "" }

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
