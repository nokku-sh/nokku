// Package egress builds HTTP clients for URLs a workspace admin chose.
package egress

import (
	"errors"
	"net"
	"net/http"
	"time"

	"code.dny.dev/ssrf"
	"github.com/caarlos0/env/v11"
)

// Far past a discovery document, a key set or an audit sink's answer.
const maxResponseBytes = 1 << 20

// AllowPrivate must stay off when multi-tenant, admins pick the URLs fetched.
type egressConfig struct {
	AllowPrivate bool `env:"NOKKU_ALLOW_PRIVATE_NETWORKS"`
}

// capped stops a read past maxResponseBytes. go-oidc reads a body whole, so an
// issuer a workspace picked could fill the memory every other workspace shares.
type capped struct{ next http.RoundTripper }

// CheckHosted refuses the setting on the hosted service, with it on any
// workspace could reach the core's network.
func CheckHosted() error {
	cfg, err := env.ParseAs[egressConfig]()
	if err != nil {
		return err
	}
	if cfg.AllowPrivate {
		return errors.New("NOKKU_ALLOW_PRIVATE_NETWORKS is set, the hosted service must not turn it on")
	}
	return nil
}

// NewClient checks the dialed address, DNS rebinding and redirects included.
func NewClient(timeout time.Duration) (*http.Client, error) {
	cfg, err := env.ParseAs[egressConfig]()
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: timeout}
	if !cfg.AllowPrivate {
		// Every IANA special-purpose range, NAT64 and 6to4 among them. Any
		// port, identity providers pick their own.
		dialer.Control = ssrf.New(ssrf.WithAnyPort()).Safe
	}
	return &http.Client{
		Timeout: timeout,
		Transport: capped{&http.Transport{
			DialContext:         dialer.DialContext,
			TLSHandshakeTimeout: timeout,
			ForceAttemptHTTP2:   true,
		}},
	}, nil
}

func (c capped) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := c.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	res.Body = http.MaxBytesReader(nil, res.Body, maxResponseBytes)
	return res, nil
}
