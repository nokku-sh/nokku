package recording

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nokku-sh/nokku/nokkud/internal/paths"
)

const (
	maxTotalSpace = 1 << 30
	maxAge        = 30 * 24 * time.Hour
)

// Uploaded recordings are gone already, so whatever this removes never reached the backend.
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
		if e.IsDir() || !strings.HasSuffix(e.Name(), castSuffix) {
			continue
		}
		// Unlinking an open file frees no space, it would only lose the recording.
		if _, busy := active.Load(filepath.Join(recordsDir, e.Name())); busy {
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

func dropPending(dir, name, reason string) {
	slog.Warn("dropping a recording that was never uploaded", "path", name, "reason", reason)
	if err := os.Remove(filepath.Join(dir, name)); err != nil {
		slog.Debug("remove recording", "path", name, "error", err)
	}
}

// The session ID is sanitized like the label, so it can never smuggle a path separator in.
func recordingPattern(now time.Time, safeLabel, sessionID string) string {
	parts := []string{now.Format("20060102T150405Z"), safeLabel}
	if sessionID != "" {
		parts = append(parts, toSnakeCase(sessionID))
	}
	return strings.Join(parts, "-") + "-*" + castSuffix
}
