package util

import (
	"net"
	"net/http"
	"strings"
)

func GetRemoteIP(header http.Header, remoteAddr string) string {
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
