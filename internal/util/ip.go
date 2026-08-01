package util

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// trustedProxies holds reverse proxy CIDRs/IPs. Client IP headers are
// honored only when the direct peer matches one of these, otherwise the
// socket peer address is used. Configured via [SetTrustedProxies].
var trustedProxies []*net.IPNet

// SetTrustedProxies configures the reverse proxies allowed to forward
// client IP headers (True-Client-Ip, X-Real-IP, X-Forwarded-For). Each
// entry is an IP or CIDR. With no entries, forwarding headers are ignored,
// the secure default.
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

func isTrustedProxy(remoteAddr string) bool {
	if len(trustedProxies) == 0 {
		return false
	}
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, ipNet := range trustedProxies {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func GetRemoteIP(header http.Header, remoteAddr string) string {
	if isTrustedProxy(remoteAddr) {
		if tcip := header.Get("True-Client-Ip"); tcip != "" {
			return canonicalizeIP(tcip)
		}
		if xrip := header.Get("X-Real-IP"); xrip != "" {
			return canonicalizeIP(xrip)
		}
		if xff := header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			return canonicalizeIP(strings.TrimSpace(first))
		}
	}
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return canonicalizeIP(ip)
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
