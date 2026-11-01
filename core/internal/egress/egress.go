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

// maxResponseBytes is far past a discovery document, a key set or the answer of an audit sink.
const maxResponseBytes = 1 << 20

// egressConfig must stay off in multi-tenant deployments, workspace admins pick the URLs the server fetches.
type egressConfig struct {
	AllowPrivate bool `env:"NOKKU_ALLOW_PRIVATE_NETWORKS"`
}

// CheckHosted refuses the setting on the hosted service. Workspaces choose these URLs there, so with it on any of them
// could reach the network the core runs in.
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
		Transport: capped{&http.Transport{
			DialContext:         dialer.DialContext,
			TLSHandshakeTimeout: timeout,
			ForceAttemptHTTP2:   true,
		}},
	}, nil
}

// capped stops a server reading on past maxResponseBytes. go-oidc reads a body whole, so an issuer a workspace picked
// could fill the memory of a core every other workspace shares.
type capped struct{ next http.RoundTripper }

func (c capped) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := c.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	res.Body = http.MaxBytesReader(nil, res.Body, maxResponseBytes)
	return res, nil
}
