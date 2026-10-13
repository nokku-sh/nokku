package paths

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

const (
	configFilename      = "config.json"
	cacheFilename       = "cache.json"
	signerStateFilename = "state.json"
	hostSignerFilename  = "ssh_host_signer.json"
	recordsDir          = "recordings"
	hostKeyName         = "ssh_host_ecdsa_key"
)

func dataDir() string {
	if dir := os.Getenv("NOKKUD_DATA_DIR"); dir != "" {
		return dir
	}
	return "/var/lib/nokkud"
}

func RecordsDir() string { return filepath.Join(dataDir(), recordsDir) }

func ConfigFile() string { return filepath.Join(dataDir(), configFilename) }

func CacheFile() string { return filepath.Join(dataDir(), cacheFilename) }

func SignerStateFile() string { return filepath.Join(dataDir(), signerStateFilename) }

func HostSignerStateFile() string { return filepath.Join(dataDir(), hostSignerFilename) }

func HostKeyPub() string { return filepath.Join(dataDir(), hostKeyName+".pub") }

func HostKeyCert() string { return filepath.Join(dataDir(), hostKeyName+"-cert.pub") }

// Verify chmods explicitly, MkdirAll leaves an existing directory's mode alone.
func Verify() error {
	dir := dataDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("cannot create directory %s: %w", dir, err)
	}
	//nolint:gosec // G302: a directory needs the execute bit to be traversable
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("cannot secure directory %s: %w", dir, err)
	}
	if err := os.MkdirAll(RecordsDir(), 0o700); err != nil {
		return fmt.Errorf("cannot create directory %s: %w", RecordsDir(), err)
	}
	return nil
}

func Cleanup() {
	if err := os.RemoveAll(dataDir()); err != nil {
		slog.Error("remove data directory", "error", err)
	}
}
