package state

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/mizuchilabs/kata/fsutil"

	"github.com/nokku-sh/nokku/cli/internal/paths"
)

// ConfigVersion goes up when an older nk would misread config.json. A file without one is version 1.
const ConfigVersion = 1

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
	// UserPublicKey signs logins, HostPublicKey the host certificates of daemons.
	UserPublicKey string `json:"user_public_key"`
	HostPublicKey string `json:"host_public_key,omitempty"`
	// RotatedAt is zero until the first rollover.
	RotatedAt time.Time `json:"rotated_at,omitzero"`
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
	// LastSyncAt is when nk sync last wrote the CA key to a manual target.
	LastSyncAt time.Time `json:"last_sync_at,omitzero"`
}

// Config keeps a session with the API that issued it.
type Config struct {
	Version int    `json:"version,omitempty"`
	APIURL  string `json:"api_url,omitempty"`
	// PEM of the API's private CA, empty when the system roots know it.
	APICA            string    `json:"api_ca,omitempty"`
	SessionToken     string    `json:"session_token,omitempty"`
	SessionExpiresAt time.Time `json:"session_expires_at,omitzero"`
	// SessionKey is the nokku.pub a sign-in sent, the only key its session gets certificates for.
	SessionKey string `json:"session_key,omitempty"`
	// SecurityKey is kept from nk login --security-key, for the same reason.
	SecurityKey bool `json:"security_key,omitzero"`
	// RequireTPM is kept from --require-tpm or NK_REQUIRE_TPM until nk logout.
	RequireTPM bool `json:"require_tpm,omitzero"`
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
	Token string
}

func (t Target) Manual() bool { return t.DaemonID == "" }

// Behind is a manual target last synced before a rollover, so it still takes only the old key.
func (t Target) Behind(ca CA) bool {
	return t.Manual() && !t.LastSyncAt.IsZero() && t.LastSyncAt.Before(ca.RotatedAt)
}

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
	s.Version = ConfigVersion
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
