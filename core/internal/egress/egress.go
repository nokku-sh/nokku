// Package egress builds HTTP clients for URLs someone in a workspace chose.
package egress

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"

	"code.dny.dev/ssrf"
)

// Far past a discovery document, a key set or an audit sink's answer.
const maxResponseBytes = 1 << 20

// Where a self-hosted identity provider or log sink lives. Link-local and
// carrier-grade NAT stay out, clouds serve instance metadata there.
var (
	privateV4 = []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	privateV6 = []netip.Prefix{
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("fc00::/7"),
	}
	// AWS serves instance metadata at fd00:ec2::254, inside the private range.
	awsMetadata = netip.MustParsePrefix("fd00:ec2::/32")

	// Set by the integration tests, their hosted server calls loopback.
	privateWhenHosted bool
)

// capped stops a read past maxResponseBytes. go-oidc reads a body whole, so an
// issuer a workspace picked could fill the memory every other workspace shares.
type capped struct{ next http.RoundTripper }

// NewClient checks the dialed address, DNS rebinding and redirects included.
// Hosted, any workspace picks the URLs, so only public addresses pass.
// Self-hosted it is the operator's own people, so private networks pass too.
func NewClient(timeout time.Duration, hosted bool) *http.Client {
	dialer := &net.Dialer{Timeout: timeout, Control: guard(hosted)}
	return &http.Client{
		Timeout: timeout,
		Transport: capped{&http.Transport{
			DialContext:         dialer.DialContext,
			TLSHandshakeTimeout: timeout,
			ForceAttemptHTTP2:   true,
		}},
	}
}

// guard refuses every IANA special-purpose range, NAT64 and 6to4 among them,
// but the private ones when allowed. Any port, identity providers pick their own.
func guard(hosted bool) func(network, address string, conn syscall.RawConn) error {
	opts := []ssrf.Option{ssrf.WithAnyPort()}
	if !hosted || privateWhenHosted {
		opts = append(opts, ssrf.WithAllowedV4Prefixes(privateV4...), ssrf.WithAllowedV6Prefixes(privateV6...))
	}
	safe := ssrf.New(opts...).Safe
	return func(network, address string, conn syscall.RawConn) error {
		if ap, err := netip.ParseAddrPort(address); err == nil && awsMetadata.Contains(ap.Addr()) {
			return fmt.Errorf("%w: %s serves instance metadata", ssrf.ErrProhibitedIP, ap.Addr())
		}
		return safe(network, address, conn)
	}
}

func (c capped) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := c.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	res.Body = http.MaxBytesReader(nil, res.Body, maxResponseBytes)
	return res, nil
}
