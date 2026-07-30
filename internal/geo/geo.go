package geo

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/iplocate/go-iplocate"
)

type Service struct {
	Token  string `env:"IPLOCATE_API_KEY"`
	client *iplocate.Client
}

func New() *Service {
	svc, err := env.ParseAs[Service]()
	if err != nil {
		return nil
	}

	svc.client = iplocate.NewClient(&http.Client{Timeout: 10 * time.Second})
	if svc.Token != "" {
		svc.client.WithAPIKey(svc.Token)
	}

	return &svc
}

func (s *Service) Lookup(addr string) string {
	location := "Unknown Location"

	if s.client == nil {
		return location
	}

	resp, err := s.client.Lookup(addr)
	if err != nil || resp == nil {
		return location
	}

	var locationParts []string
	if resp.City != nil && *resp.City != "" {
		locationParts = append(locationParts, *resp.City)
	}
	if resp.Subdivision != nil && *resp.Subdivision != "" {
		if resp.City == nil || *resp.City != *resp.Subdivision {
			locationParts = append(locationParts, *resp.Subdivision)
		}
	}
	if resp.Country != nil && *resp.Country != "" {
		locationParts = append(locationParts, *resp.Country)
	}

	var privacyFlags []string
	if resp.Privacy.IsVPN {
		privacyFlags = append(privacyFlags, "VPN")
	}
	if resp.Privacy.IsTor {
		privacyFlags = append(privacyFlags, "Tor")
	}
	if resp.Privacy.IsProxy {
		privacyFlags = append(privacyFlags, "Proxy")
	}
	if resp.Privacy.IsIcloudRelay {
		privacyFlags = append(privacyFlags, "iCloud Relay")
	}

	if len(locationParts) > 0 {
		location = strings.Join(locationParts, ", ")
	}
	if len(privacyFlags) > 0 {
		location += fmt.Sprintf(" (%s)", strings.Join(privacyFlags, "/"))
	}

	return location
}
