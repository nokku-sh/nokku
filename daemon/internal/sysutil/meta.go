package sysutil

import (
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
)

// Container, VM, bridge and Kubernetes CNI plumbing never makes a useful SSH endpoint.
var noisePrefixes = []string{
	"docker", "veth", "br-", "virbr", "vmnet",
	"vboxnet", "vnic", "vethernet",
	"lo", "dummy", "teql", "gre", "sit",
	"ip6tnl", "ip6gre",
	"cali", "flannel", "cni",
	"kube", "weave",
	"cilium", "antrea",
	"podman", "containerd",
}

// A WireGuard or Tailscale address is often the best way to reach the server.
var tunnelPrefixes = []string{"wg", "tun", "tap", "utun", "ppp"}

func Metadata() map[string]string {
	hostname, _ := os.Hostname()
	return map[string]string{
		"hostname": hostname,
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
	}
}

func PrivateIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var ips []string
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Point-to-point links are usually VPN tunnels, so only known mesh interfaces make useful endpoints.
		if i.Flags&net.FlagPointToPoint != 0 && !hasAnyPrefix(i.Name, tunnelPrefixes) {
			continue
		}

		if isNoiseInterface(i.Name) {
			continue
		}

		var addrs []net.Addr
		addrs, err = i.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}

			ip = ip.Unmap()

			if !ip.Is4() {
				continue
			}

			if !isPublicOrPrivateNIC(ip) {
				continue
			}

			ips = append(ips, ip.String())
			if len(ips) >= 2 {
				return ips
			}
		}
	}
	return ips
}

func isNoiseInterface(name string) bool {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "hyper-v") {
		return true
	}
	return hasAnyPrefix(lower, noisePrefixes)
}

func hasAnyPrefix(name string, prefixes []string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range prefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func isPublicOrPrivateNIC(ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() ||
		ip.IsUnspecified() {
		return false
	}
	return true
}
