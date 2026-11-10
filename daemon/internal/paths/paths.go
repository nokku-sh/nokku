package paths

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

const (
	stateFilename       = "daemon.json"
	signerStateFilename = "state.json"
	recordsDir          = "recordings"
	hostKeyName         = "ssh_host_ecdsa_key"
	reportsFilename     = "connections.jsonl"
)

func RecordsDir() string { return filepath.Join(dataDir(), recordsDir) }

func StateFile() string { return filepath.Join(dataDir(), stateFilename) }

// ReportsFile holds the connection events the core does not have yet.
func ReportsFile() string { return filepath.Join(dataDir(), reportsFilename) }

func SignerStateFile() string { return filepath.Join(dataDir(), signerStateFilename) }

func HostKey() string { return filepath.Join(dataDir(), hostKeyName) }

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

func dataDir() string {
	if dir := os.Getenv("NOKKUD_DATA_DIR"); dir != "" {
		return dir
	}
	return "/var/lib/nokkud"
}
