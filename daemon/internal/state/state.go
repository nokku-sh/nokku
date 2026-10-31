package state

import (
	"errors"
	"log/slog"
	"maps"
	"sync"
	"sync/atomic"

	"github.com/mizuchilabs/kata/fsutil"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

const DefaultAPIURL = "https://app.nokku.sh"

// ErrReplaced is a nokkud enroll on this host while the service runs. The new enrollment takes over at the next start.
var ErrReplaced = errors.New("another enrollment replaced this one on disk, restart nokkud to use it")

// Config is the enrollment.
type Config struct {
	TargetID string `json:"target_id,omitempty"`
	DaemonID string `json:"daemon_id,omitempty"`
	APIURL   string `json:"api_url,omitempty"`
	// APICA is the PEM of a private CA for the API, empty when the system roots know its certificate.
	APICA        string `json:"api_ca,omitempty"`
	SessionToken string `json:"session_token,omitempty"`
}

// Access is everything one sync decides. Nobody changes one once it is stored, so it is read without a lock.
type Access struct {
	Principals   map[string][]string     `json:"principals,omitempty"`
	DaemonConfig *nokkuv1.DaemonConfig   `json:"daemon_config,omitempty"`
	CA           string                  `json:"ca,omitempty"`
	RetiredCAs   []*nokkuv1.RetiredCAKey `json:"retired_cas,omitempty"`
	// HostCA signs the host certificate. Logins are only ever checked against CA and RetiredCAs.
	HostCA       string `json:"host_ca,omitempty"`
	StateVersion int64  `json:"state_version,omitzero"`
}

// State is the daemon's one state file. Its Config is set before the client starts and only read after.
type State struct {
	Config

	access atomic.Pointer[Access]
	// saved is the state version on disk, the one the heartbeat reports.
	saved atomic.Int64

	mu sync.Mutex
	// owner is the daemon the file named when this state was read, a save never writes over another one.
	owner string
}

type file struct {
	Config

	Access *Access `json:"access,omitempty"`
}

// AccessFrom is the access a sync answer gives.
func AccessFrom(res *nokkuv1.SyncDaemonResponse) *Access {
	principals := make(map[string][]string, len(res.GetPrincipals()))
	for _, p := range res.GetPrincipals() {
		principals[p.GetUsername()] = p.GetCertPrincipals()
	}
	return &Access{
		Principals:   validAccounts(principals),
		DaemonConfig: res.GetConfig(),
		CA:           res.GetCaPublicKey(),
		RetiredCAs:   res.GetRetiredCaKeys(),
		HostCA:       res.GetHostCaPublicKey(),
		StateVersion: res.GetStateVersion(),
	}
}

// validAccounts drops every name that is no valid account, so neither the core nor the file can sneak in an unsafe one.
func validAccounts(principals map[string][]string) map[string][]string {
	maps.DeleteFunc(principals, func(name string, _ []string) bool {
		if login.ValidUsername(name) {
			return false
		}
		slog.Debug("skipping invalid username", "username", name)
		return true
	})
	return principals
}

// New holds cfg and no access.
func New(cfg Config) *State {
	s := &State{Config: cfg}
	s.access.Store(&Access{})
	return s
}

// Load starts empty when the file is missing and ignores a corrupted one, the next sync rebuilds it.
func Load() (*State, error) {
	var f file
	if err := fsutil.LoadJSON(paths.StateFile(), &f); err != nil {
		return nil, err
	}
	s := New(f.Config)
	s.owner = f.DaemonID
	if f.Access != nil {
		f.Access.Principals = validAccounts(f.Access.Principals)
		s.access.Store(f.Access)
		s.saved.Store(f.Access.StateVersion)
	}
	return s, nil
}

func (s *State) Access() *Access {
	return s.access.Load()
}

// SetAccess swaps the access whole. It reaches the disk with the next Save.
func (s *State) SetAccess(a *Access) {
	s.access.Store(a)
}

// Save writes both halves as one file, unless that file now names another daemon than the one this state was read with.
func (s *State) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owner != "" {
		var onDisk file
		if err := fsutil.LoadJSON(paths.StateFile(), &onDisk); err == nil && onDisk.DaemonID != "" &&
			onDisk.DaemonID != s.owner {
			return ErrReplaced
		}
	}
	a := s.Access()
	if err := fsutil.SaveJSON(paths.StateFile(), file{Config: s.Config, Access: a}, 0o600); err != nil {
		return err
	}
	s.owner = s.DaemonID
	s.saved.Store(a.StateVersion)
	return nil
}

// Dropped is the state after a rejection: the API kept, the enrollment and access gone. It saves only over this one.
func (s *State) Dropped() *State {
	d := New(Config{APIURL: s.APIURL, APICA: s.APICA})
	s.mu.Lock()
	d.owner = s.owner
	s.mu.Unlock()
	return d
}

func (s *State) SavedVersion() int64 {
	return s.saved.Load()
}
