package recording

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

const (
	maxTotalSpace = 1 << 30
	maxAge        = 30 * 24 * time.Hour
)

// Uploaded recordings are gone, so whatever this drops never reached the core.
func enforceRetention() error {
	recordsDir := paths.RecordsDir()
	entries, err := os.ReadDir(recordsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	cutoff := time.Now().Add(-maxAge)
	var kept []os.FileInfo
	var total int64
	for _, e := range entries {
		if e.IsDir() || !isRecording(e.Name()) {
			continue
		}
		// Unlinking a file in use frees no space, it only loses the recording.
		if beingWritten(filepath.Join(recordsDir, e.Name())) {
			continue
		}
		var info os.FileInfo
		info, err = e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			dropPending(recordsDir, info.Name(), "expired")
			continue
		}
		kept = append(kept, info)
		total += info.Size()
	}

	slices.SortFunc(kept, func(a, b os.FileInfo) int {
		return a.ModTime().Compare(b.ModTime())
	})
	for total > maxTotalSpace && len(kept) > 0 {
		total -= kept[0].Size()
		dropPending(recordsDir, kept[0].Name(), "over the space limit")
		kept = kept[1:]
	}
	return nil
}

func isRecording(name string) bool {
	return strings.HasSuffix(name, partSuffix) || strings.HasSuffix(name, castSuffix)
}

// The recorder holds an exclusive lock on its file until it closes it.
func beingWritten(path string) bool {
	f, err := os.Open(path) // #nosec G304 - a file from the recordings dir
	if err != nil {
		return false
	}
	defer f.Close()
	return errors.Is(syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB), syscall.EWOULDBLOCK)
}

func dropPending(dir, name, reason string) {
	slog.Warn("dropping a recording that was never uploaded", "path", name, "reason", reason)
	if err := os.Remove(filepath.Join(dir, name)); err != nil {
		slog.Debug("remove recording", "path", name, "error", err)
	}
}
