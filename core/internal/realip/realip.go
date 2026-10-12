// Package realip finds the client address behind trusted proxies.
package realip

import (
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
)

var trustedProxies []*net.IPNet

// SetTrustedProxies with no entries ignores forwarding headers. The list the server starts with is in config.
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

func isTrustedProxy(ip net.IP) bool {
	for _, ipNet := range trustedProxies {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// Bucket is Client as a key for rate limits and logs, where one IPv6 /64 counts as one client.
func Bucket(header http.Header, remoteAddr string) string {
	return canonicalizeIP(Client(header, remoteAddr))
}

// Client reads only X-Forwarded-For from a trusted proxy. It is the rightmost hop that is not a trusted proxy.
func Client(header http.Header, remoteAddr string) string {
	peer := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		peer = host
	}
	peerIP := net.ParseIP(peer)
	if peerIP == nil || !isTrustedProxy(peerIP) {
		return peer
	}
	hops := strings.Split(strings.Join(header.Values("X-Forwarded-For"), ","), ",")
	for _, hop := range slices.Backward(hops) {
		ip := net.ParseIP(strings.TrimSpace(hop))
		if ip == nil {
			break
		}
		if !isTrustedProxy(ip) {
			return ip.String()
		}
	}
	return peer
}

// Proto reads only X-Forwarded-Proto from a trusted proxy. It is the scheme the client reached that proxy with.
func Proto(header http.Header, remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	if ip := net.ParseIP(host); ip == nil || !isTrustedProxy(ip) {
		return ""
	}
	return header.Get("X-Forwarded-Proto")
}

func canonicalizeIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	// Collapse IPv6 to /64 prefix so a single /64 block shares one bucket.
	if parsed.To4() == nil {
		return parsed.Mask(net.CIDRMask(64, 128)).String()
	}
	return parsed.String()
}
