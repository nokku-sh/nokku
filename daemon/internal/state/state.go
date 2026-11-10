package state

import (
	"errors"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mizuchilabs/kata/fsutil"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

const DefaultAPIURL = "https://app.nokku.sh"

var errReplaced = errors.New("another enrollment replaced this one on disk, restart nokkud to use it")

// Config is the enrollment.
type Config struct {
	TargetID string `json:"target_id,omitempty"`
	DaemonID string `json:"daemon_id,omitempty"`
	APIURL   string `json:"api_url,omitempty"`
	// APICA is a private CA's PEM, empty when the system roots know the API.
	APICA        string `json:"api_ca,omitempty"`
	SessionToken string `json:"session_token,omitempty"`
}

// Access is one sync's outcome. Never change a stored one, reads take no lock.
type Access struct {
	Principals   map[string][]string   `json:"principals,omitempty"`
	DaemonConfig *nokkuv1.DaemonConfig `json:"daemon_config,omitempty"`
	CA           string                `json:"ca,omitempty"`
	// HostCA signs the host cert. Logins only ever check CA.
	HostCA string `json:"host_ca,omitempty"`
	// StateHash is the core's hash of the sync this came from. The daemon only hands it back.
	StateHash []byte `json:"state_hash,omitempty"`
	// SyncedAt is when the core last said so, by this host's clock. The sshd counts from it.
	SyncedAt time.Time `json:"synced_at,omitzero"`
}

// State has a Config set before the client starts and only read after.
type State struct {
	Config

	access atomic.Pointer[Access]
	// saved is the access on disk, the one the heartbeat reports.
	saved atomic.Pointer[Access]

	mu sync.Mutex
	// The daemon the file named at load, a save never overwrites another.
	owner string
}

type file struct {
	Config

	Access *Access `json:"access,omitempty"`
}

// AccessFrom keeps only principals that name this server and the account they
// sit under, so a wrong list from the core can't open another account.
func AccessFrom(res *nokkuv1.SyncDaemonResponse, targetID string) *Access {
	principals := make(map[string][]string, len(res.GetPrincipals()))
	for _, p := range res.GetPrincipals() {
		username := p.GetUsername()
		principals[username] = slices.DeleteFunc(slices.Clone(p.GetCertPrincipals()), func(principal string) bool {
			parts, ok := login.ParsePrincipal(principal)
			if ok && parts.TargetID == targetID && parts.Username == username {
				return false
			}
			slog.Warn(
				"skipping a principal for another server or account",
				"username",
				username,
				"principal",
				principal,
			)
			return true
		})
	}
	return &Access{
		Principals:   validAccounts(principals),
		DaemonConfig: res.GetConfig(),
		CA:           res.GetCaPublicKey(),
		HostCA:       res.GetHostCaPublicKey(),
		StateHash:    res.GetStateHash(),
		SyncedAt:     time.Now(),
	}
}

// validAccounts keeps the core or the file from sneaking in an unsafe name.
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

func New(cfg Config) *State {
	s := &State{Config: cfg}
	s.access.Store(&Access{})
	s.saved.Store(&Access{})
	return s
}

// Load ignores a missing or corrupted file. A sync rebuilds the access, but the
// enrollment is in there too, so a corrupted file means enrolling again.
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
		s.saved.Store(f.Access)
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

// Save never writes over a file that now names another daemon.
func (s *State) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owner != "" {
		var onDisk file
		if err := fsutil.LoadJSON(paths.StateFile(), &onDisk); err == nil && onDisk.DaemonID != "" &&
			onDisk.DaemonID != s.owner {
			return errReplaced
		}
	}
	a := s.Access()
	if err := fsutil.SaveJSON(paths.StateFile(), file{Config: s.Config, Access: a}, 0o600); err != nil {
		return err
	}
	s.owner = s.DaemonID
	s.saved.Store(a)
	return nil
}

// Dropped is the state after a rejection. It saves only over this one.
func (s *State) Dropped() *State {
	d := New(Config{APIURL: s.APIURL, APICA: s.APICA})
	s.mu.Lock()
	d.owner = s.owner
	s.mu.Unlock()
	return d
}

// Saved is the access that reached the disk, which may be one sync behind Access.
func (s *State) Saved() *Access {
	return s.saved.Load()
}
