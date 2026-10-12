package state

import (
	"encoding/json"
	"log/slog"
	"slices"
	"sync"

	"github.com/mizuchilabs/kata/fsutil"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/nokkud/internal/paths"
)

// Cache backs SSH access decisions when the backend is unreachable.
type Cache struct {
	mu   sync.RWMutex
	data cacheJSON
}

// Unexported so every access goes through the mutex.
type cacheJSON struct {
	Principals   map[string][]string     `json:"principals"`
	StateVersion int64                   `json:"state_version,omitempty"`
	DaemonConfig *nokkuv1.DaemonConfig   `json:"daemon_config,omitempty"`
	CA           string                  `json:"ca,omitempty"`
	RetiredCAs   []*nokkuv1.RetiredCAKey `json:"retired_cas,omitempty"`
}

func NewCache() *Cache {
	return &Cache{data: cacheJSON{Principals: make(map[string][]string)}}
}

// CertPrincipals returns a copy. The principals are only ever compared as whole strings.
func (c *Cache) CertPrincipals(username string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return slices.Clone(c.data.Principals[username])
}

func (c *Cache) GetStateVersion() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data.StateVersion
}

func (c *Cache) SetDaemonConfig(dc *nokkuv1.DaemonConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data.DaemonConfig = dc
}

// DaemonConfig is shared, callers must treat it as read-only.
func (c *Cache) DaemonConfig() *nokkuv1.DaemonConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data.DaemonConfig
}

// CAs returns the active CA key and the rolled-over ones still trusted. The retired keys are read-only.
func (c *Cache) CAs() (active string, retired []*nokkuv1.RetiredCAKey) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data.CA, c.data.RetiredCAs
}

// Replace swaps everything at once, so a concurrent login never sees an empty map mid-sync.
func (c *Cache) Replace(
	principals map[string][]string,
	dc *nokkuv1.DaemonConfig,
	ca string,
	retiredCAs []*nokkuv1.RetiredCAKey,
	version int64,
) {
	next := validPrincipals(principals)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = cacheJSON{
		Principals:   next,
		StateVersion: version,
		DaemonConfig: dc,
		CA:           ca,
		RetiredCAs:   retiredCAs,
	}
}

func validPrincipals(m map[string][]string) map[string][]string {
	next := make(map[string][]string, len(m))
	for principal, uuids := range m {
		if err := validatePrincipal(principal); err != nil {
			slog.Debug("skipping invalid principal", "error", err)
			continue
		}
		next[principal] = slices.Clone(uuids)
	}
	return next
}

func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = cacheJSON{Principals: make(map[string][]string)}
}

// Load ignores a corrupted file so the next sync rebuilds it.
func (c *Cache) Load() error {
	return fsutil.LoadJSON(paths.CacheFile(), c)
}

func (c *Cache) Save() error {
	return fsutil.SaveJSON(paths.CacheFile(), c, 0o640)
}

func (c *Cache) MarshalJSON() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return json.Marshal(c.data)
}

// UnmarshalJSON validates like Replace, so a hand-edited file cannot sneak in an unsafe name.
func (c *Cache) UnmarshalJSON(data []byte) error {
	var next cacheJSON
	if err := json.Unmarshal(data, &next); err != nil {
		return err
	}
	next.Principals = validPrincipals(next.Principals)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = next
	return nil
}
