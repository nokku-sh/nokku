package geo

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/ip2location/ip2location-go/v9"
)

const (
	// downloadBase is the token-authenticated IP2Location download endpoint.
	downloadBase = "https://www.ip2location.com/download"

	// liteDBFile is the subscribed database variant: Country, Region, City.
	liteDBFile = "DB3LITEBIN"

	// downloadTimeout bounds a single fetch attempt.
	downloadTimeout = 30 * time.Second

	// fallbackLocation is returned when no database is loaded.
	fallbackLocation = "Unknown Location"
)

// Service resolves IP addresses to human-readable locations using a local
// IP2Location BIN database. The database is downloaded from IP2Location once
// and cached on disk; lookups never leave the server.
type Service struct {
	Token  string `env:"IP2LOCATION_TOKEN"`
	DBPath string `env:"IP2LOCATION_DB_PATH" envDefault:"data/ip2location.bin"`

	db atomic.Pointer[ip2location.DB]
}

func New() *Service {
	svc, err := env.ParseAs[Service]()
	if err != nil {
		slog.Warn("geo: parse environment", "error", err)
		return &Service{}
	}

	if db, err := ip2location.OpenDB(svc.DBPath); err == nil {
		svc.db.Store(db)
		return &svc
	}

	if svc.Token == "" {
		slog.Warn("geo: no local database and no token", "path", svc.DBPath)
		return &svc
	}

	// No cached database yet: fetch it in the background so startup is not
	// blocked on the download. Until it lands, lookups fall back.
	slog.Info("geo: downloading ip2location database", "path", svc.DBPath)
	go svc.fetch()
	return &svc
}

// Lookup returns a human-readable location for addr, or the fallback string
// when no database is loaded or the address cannot be resolved.
func (s *Service) Lookup(addr string) string {
	db := s.db.Load()
	if db == nil {
		return fallbackLocation
	}

	res, err := db.Get_all(addr)
	if err != nil {
		return fallbackLocation
	}

	var parts []string
	if res.City != "" {
		parts = append(parts, res.City)
	}
	if res.Region != "" && res.Region != res.City {
		parts = append(parts, res.Region)
	}
	if res.Country_long != "" {
		parts = append(parts, res.Country_long)
	}
	if len(parts) == 0 {
		return fallbackLocation
	}
	return strings.Join(parts, ", ")
}

// fetch downloads the database, caches it on disk and loads it.
func (s *Service) fetch() {
	ctx, cancel := context.WithTimeout(context.Background(), downloadTimeout)
	defer cancel()

	url := fmt.Sprintf("%s?token=%s&file=%s", downloadBase, s.Token, liteDBFile)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		slog.Warn("geo: build download request", "error", err)
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.Warn("geo: download failed", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("geo: download failed", "status", resp.StatusCode)
		return
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Warn("geo: read download", "error", err)
		return
	}

	// LITE downloads are served gzip-compressed; detect and unwrap.
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			slog.Warn("geo: unzip database", "error", err)
			return
		}
		data, err = io.ReadAll(gz)
		_ = gz.Close()
		if err != nil {
			slog.Warn("geo: unzip database", "error", err)
			return
		}
	}

	if err := os.MkdirAll(filepath.Dir(s.DBPath), 0o750); err != nil {
		slog.Warn("geo: create database directory", "error", err)
		return
	}

	tmp := s.DBPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		slog.Warn("geo: cache database", "error", err)
		return
	}
	if err := os.Rename(tmp, s.DBPath); err != nil {
		slog.Warn("geo: cache database", "error", err)
		return
	}

	db, err := ip2location.OpenDB(s.DBPath)
	if err != nil {
		slog.Warn("geo: open database", "error", err)
		return
	}
	s.db.Store(db)
	slog.Info("geo: database loaded", "path", s.DBPath)
}
