package util

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"

	"github.com/caarlos0/env/v11"
)

var errNotPublic = errors.New("destination address is not public")

// cgnat is internal on most clouds.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// egressConfig must stay off in multi-tenant deployments, since workspace
// admins pick the URLs the server fetches.
type egressConfig struct {
	AllowPrivate bool `env:"NOKKU_ALLOW_PRIVATE_NETWORKS"`
}

// NewEgressClient is for URLs a workspace admin chose. It refuses non-public
// addresses unless NOKKU_ALLOW_PRIVATE_NETWORKS is set. The check runs on the
// dialed address, so DNS rebinding and redirects cannot slip past it.
func NewEgressClient(timeout time.Duration) (*http.Client, error) {
	cfg, err := env.ParseAs[egressConfig]()
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: timeout}
	if !cfg.AllowPrivate {
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return err
			}
			ip := ap.Addr().Unmap()
			if !ip.IsGlobalUnicast() || ip.IsPrivate() || cgnat.Contains(ip) {
				return errNotPublic
			}
			return nil
		}
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
