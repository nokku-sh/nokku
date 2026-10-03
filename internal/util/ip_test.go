package util

import (
	"net/http"
	"testing"
)

// setProxies resets the package-level trusted proxy list and returns a
// cleanup that restores the empty (secure) default.
func setProxies(t *testing.T, proxies ...string) {
	t.Helper()
	if err := SetTrustedProxies(proxies); err != nil {
		t.Fatalf("SetTrustedProxies(%v): %v", proxies, err)
	}
	t.Cleanup(func() {
		if err := SetTrustedProxies(nil); err != nil {
			t.Errorf("resetting trusted proxies: %v", err)
		}
	})
}

func TestGetRemoteIP_NoTrustedProxies(t *testing.T) {
	setProxies(t)

	tests := []struct {
		name       string
		header     http.Header
		remoteAddr string
		want       string
	}{
		{
			name: "headers are ignored without trusted proxies",
			header: http.Header{
				"X-Forwarded-For": {"203.0.113.9"},
				"True-Client-Ip":  {"203.0.113.10"},
			},
			remoteAddr: "198.51.100.1:12345",
			want:       "198.51.100.1",
		},
		{
			name:       "plain IP without port",
			remoteAddr: "198.51.100.1",
			want:       "198.51.100.1",
		},
		{
			name:       "IPv6 peer is collapsed to /64",
			remoteAddr: "[2001:db8:abcd:1234:5678:9abc:def0:1234]:443",
			want:       "2001:db8:abcd:1234::",
		},
		{
			name:       "garbage remote addr passed through",
			remoteAddr: "not-an-addr",
			want:       "not-an-addr",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetRemoteIP(tt.header, tt.remoteAddr); got != tt.want {
				t.Errorf("GetRemoteIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetRemoteIP_TrustedProxyHeaders(t *testing.T) {
	setProxies(t, "10.0.0.0/8")

	header := func(pairs ...string) http.Header {
		h := http.Header{}
		for i := 0; i < len(pairs); i += 2 {
			h.Add(pairs[i], pairs[i+1])
		}
		return h
	}

	tests := []struct {
		name       string
		header     http.Header
		remoteAddr string
		want       string
	}{
		{
			name: "client-sent True-Client-Ip and X-Real-IP are never read",
			header: header(
				"True-Client-Ip", "203.0.113.1",
				"X-Real-IP", "203.0.113.2",
				"X-Forwarded-For", "203.0.113.3",
			),
			remoteAddr: "10.1.2.3:5555",
			want:       "203.0.113.3",
		},
		{
			name:       "without XFF the other headers do not count",
			header:     header("True-Client-Ip", "203.0.113.1", "X-Real-IP", "203.0.113.2"),
			remoteAddr: "10.1.2.3:5555",
			want:       "10.1.2.3",
		},
		{
			name:       "rightmost hop that is not a trusted proxy",
			header:     header("X-Forwarded-For", "203.0.113.4, 10.1.2.3, 10.0.0.1"),
			remoteAddr: "10.1.2.3:5555",
			want:       "203.0.113.4",
		},
		{
			name:       "a client-sent left entry is not the client",
			header:     header("X-Forwarded-For", "198.51.100.99, 203.0.113.4"),
			remoteAddr: "10.1.2.3:5555",
			want:       "203.0.113.4",
		},
		{
			name:       "several XFF header lines are one list",
			header:     header("X-Forwarded-For", "198.51.100.99", "X-Forwarded-For", "203.0.113.4"),
			remoteAddr: "10.1.2.3:5555",
			want:       "203.0.113.4",
		},
		{
			name:       "only trusted hops fall back to the peer",
			header:     header("X-Forwarded-For", "10.0.0.9"),
			remoteAddr: "10.1.2.3:5555",
			want:       "10.1.2.3",
		},
		{
			name:       "an entry that is not an IP falls back to the peer",
			header:     header("X-Forwarded-For", "203.0.113.4, not-an-ip"),
			remoteAddr: "10.1.2.3:5555",
			want:       "10.1.2.3",
		},
		{
			name:       "empty XFF falls back to the peer",
			header:     header("X-Forwarded-For", "  "),
			remoteAddr: "10.1.2.3:5555",
			want:       "10.1.2.3",
		},
		{
			name:       "untrusted peer: spoofed header ignored",
			header:     header("X-Forwarded-For", "203.0.113.66"),
			remoteAddr: "198.51.100.7:5555",
			want:       "198.51.100.7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetRemoteIP(tt.header, tt.remoteAddr); got != tt.want {
				t.Errorf("GetRemoteIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetRemoteIP_TrustedProxyCIDR(t *testing.T) {
	setProxies(t, "10.0.0.0/8", "192.168.1.1")

	tests := []struct {
		name   string
		peer   string
		header bool
		want   string
	}{
		{"peer inside /8", "10.0.0.1:80", true, "203.0.113.1"},
		{"peer outside /8", "172.16.0.1:80", false, "172.16.0.1"},
		{"exact IP entry", "192.168.1.1:80", true, "203.0.113.1"},
		{"IP entry does not cover subnet", "192.168.1.2:80", false, "192.168.1.2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			if tt.header {
				h.Set("X-Forwarded-For", "203.0.113.1")
			}
			if got := GetRemoteIP(h, tt.peer); got != tt.want {
				t.Errorf("GetRemoteIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetRemoteIP_HeaderIPCanonicalization(t *testing.T) {
	setProxies(t, "10.0.0.0/8")

	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"v4-mapped v6 normalized to v4", "::ffff:203.0.113.1", "203.0.113.1"},
		{"v6 collapsed to /64", "2001:db8:abcd:1234:5678:9abc:def0:1234", "2001:db8:abcd:1234::"},
		{"a port is not an IP, the peer wins", "203.0.113.1:8080", "10.1.2.3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			h.Set("X-Forwarded-For", tt.header)
			if got := GetRemoteIP(h, "10.1.2.3:80"); got != tt.want {
				t.Errorf("GetRemoteIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSetTrustedProxies(t *testing.T) {
	tests := []struct {
		name    string
		proxies []string
		wantErr bool
	}{
		{"empty list is valid", nil, false},
		{"plain IP is valid", []string{"1.2.3.4"}, false},
		{"IPv6 is valid", []string{"2001:db8::1"}, false},
		{"CIDR is valid", []string{"10.0.0.0/8"}, false},
		{"whitespace entries skipped", []string{"", "   ", "10.0.0.0/8"}, false},
		{"garbage rejected", []string{"nonsense"}, true},
		{"partial garbage rejects whole list", []string{"10.0.0.0/8", "nonsense"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SetTrustedProxies(tt.proxies)
			if (err != nil) != tt.wantErr {
				t.Errorf(
					"SetTrustedProxies(%v) error = %v, wantErr %v",
					tt.proxies,
					err,
					tt.wantErr,
				)
			}
		})
	}
}
