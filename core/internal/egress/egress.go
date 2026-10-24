// Package egress builds HTTP clients for URLs a workspace admin chose.
package egress

import (
	"net"
	"net/http"
	"time"

	"code.dny.dev/ssrf"
	"github.com/caarlos0/env/v11"
)

// egressConfig must stay off in multi-tenant deployments, workspace admins pick the URLs the server fetches.
type egressConfig struct {
	AllowPrivate bool `env:"NOKKU_ALLOW_PRIVATE_NETWORKS"`
}

// NewClient checks the dialed address, so DNS rebinding and redirects cannot slip past it.
func NewClient(timeout time.Duration) (*http.Client, error) {
	cfg, err := env.ParseAs[egressConfig]()
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: timeout}
	if !cfg.AllowPrivate {
		// Every IANA special-purpose range, NAT64 and 6to4 among them. Any port, identity providers pick their own.
		dialer.Control = ssrf.New(ssrf.WithAnyPort()).Safe
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:         dialer.DialContext,
			TLSHandshakeTimeout: timeout,
			ForceAttemptHTTP2:   true,
		},
	}, nil
}
