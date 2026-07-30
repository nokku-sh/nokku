// Package location provides functions for retrieving the location of a request.
package location

import (
	"embed"
	"net"
	"strings"

	"github.com/oschwald/geoip2-golang"
	"golang.org/x/exp/slog"
)

//go:embed geodb
var geoFS embed.FS

type Service struct {
	db *geoip2.Reader
}

func New() *Service {
	fileBytes, err := geoFS.ReadFile("geodb/GeoLite2-City.mmdb")
	if err != nil {
		slog.Warn("failed to read geoip database, location lookups disabled.", "error", err)
		return &Service{db: nil}
	}

	db, err := geoip2.FromBytes(fileBytes)
	if err != nil {
		slog.Error("failed to open geoip database", "error", err)
		return &Service{db: nil}
	}
	return &Service{db: db}
}

// GetLocation extracts the IP and returns a string.
func (l *Service) GetLocation(ipStr string) string {
	if l.db == nil {
		return "Unknown Location"
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "Unknown Location"
	}

	record, err := l.db.City(ip)
	if err != nil || record == nil {
		return "Unknown Location"
	}

	var loc []string
	if record.City.Names["en"] != "" {
		loc = append(loc, record.City.Names["en"])
	}
	if record.Country.Names["en"] != "" {
		loc = append(loc, record.Country.Names["en"])
	}

	if len(loc) == 0 {
		return "Unknown Location"
	}

	// return only "City, Country"
	return strings.Join(loc, ", ")
}
