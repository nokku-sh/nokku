package state

import (
	"github.com/mizuchilabs/kata/fsutil"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

const DefaultAPIURL = "https://app.nokku.sh"

// Config is the persisted enrollment state. The core-synced daemon config lives in [Cache].
type Config struct {
	TargetID string `json:"target_id,omitempty"`
	DaemonID string `json:"daemon_id,omitempty"`
	APIURL   string `json:"api_url,omitempty"`
	// APICA is the PEM of a private CA for the API, empty when the system roots know its certificate.
	APICA        string `json:"api_ca,omitempty"`
	SessionToken string `json:"session_token,omitempty"`
}

func (c *Config) Load() error {
	return fsutil.LoadJSON(paths.ConfigFile(), c)
}

func (c *Config) Save() error {
	return fsutil.SaveJSON(paths.ConfigFile(), c, 0o600)
}
