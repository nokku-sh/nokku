// Package realip finds the client address behind a reverse proxy.
package realip

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
)

var (
	trustedProxies []*net.IPNet

	warnUntrusted sync.Once
)

// SetTrustedProxies with no entries trusts a loopback or private peer for one
// hop. A list replaces that, and X-Forwarded-For skips its entries too.
func SetTrustedProxies(proxies []string) error {
	trustedProxies = nil
	for _, raw := range proxies {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		ipNet, err := parseProxy(entry)
		if err != nil {
			return fmt.Errorf("invalid trusted proxy %q: %w", entry, err)
		}
		trustedProxies = append(trustedProxies, ipNet)
	}
	return nil
}

func parseProxy(entry string) (*net.IPNet, error) {
	if ip := net.ParseIP(entry); ip != nil {
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
	}
	_, ipNet, err := net.ParseCIDR(entry)
	if err != nil {
		return nil, err
	}
	return ipNet, nil
}

// Bucket is Client as a rate-limit key, one IPv6 /64 counts as one client.
// Anything stored takes Client, so the audit log keeps the exact address.
func Bucket(header http.Header, remoteAddr string) string {
	return canonicalizeIP(Client(header, remoteAddr))
}

// Client is the rightmost unlisted forwarded hop, if the peer may forward.
func Client(header http.Header, remoteAddr string) string {
	peer := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		peer = host
	}
	peerIP := net.ParseIP(peer)
	if peerIP == nil {
		return peer
	}
	forwarded := header.Values("X-Forwarded-For")
	if !mayForward(peerIP) {
		if len(forwarded) > 0 {
			warnUntrusted.Do(func() {
				slog.Warn("ignoring X-Forwarded-For from an address that is not a trusted proxy, "+
					"if it is your proxy add it to NOKKU_TRUSTED_PROXIES or every client shows up as it",
					"peer", peer)
			})
		}
		return peer
	}
	hops := strings.Split(strings.Join(forwarded, ","), ",")
	for _, hop := range slices.Backward(hops) {
		ip := parseHop(strings.TrimSpace(hop))
		if ip == nil {
			break
		}
		if !isTrustedProxy(ip) {
			return ip.String()
		}
	}
	return peer
}

// Without a list, anything on a private network can name any client.
func mayForward(peer net.IP) bool {
	if len(trustedProxies) == 0 {
		return peer.IsLoopback() || peer.IsPrivate()
	}
	return isTrustedProxy(peer)
}

func isTrustedProxy(ip net.IP) bool {
	for _, ipNet := range trustedProxies {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// parseHop also takes an address with a port, Azure's gateways send one.
func parseHop(hop string) net.IP {
	if ip := net.ParseIP(hop); ip != nil {
		return ip
	}
	if host, _, err := net.SplitHostPort(hop); err == nil {
		return net.ParseIP(host)
	}
	return nil
}

func canonicalizeIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if parsed.To4() == nil {
		return parsed.Mask(net.CIDRMask(64, 128)).String()
	}
	return parsed.String()
}
