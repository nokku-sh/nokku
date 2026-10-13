package sysutil

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsNoiseInterface(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"docker0", true},
		{"veth123", true},
		{"br-1", true},
		{"virbr0", true},
		{"lo", true},
		{"dummy0", true},
		{"cali-ab12", true},
		{"flannel.1", true},
		{"bond1", false},
		{"eth0", false},
		{"enp3s0", false},
		{"wg0", false},
		{"utun3", false},
		{"Hyper-V Virtual Ethernet Adapter", true},
		{"DOCKER0", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := assert.New(t)
			is.Equal(tt.want, isNoiseInterface(tt.name))
		})
	}
}

func TestHasAnyPrefixIsCaseInsensitive(t *testing.T) {
	is := assert.New(t)
	is.True(hasAnyPrefix("ETH0", []string{"eth"}))
	is.False(hasAnyPrefix("veth0", []string{"eth"}))
}

func TestIsPublicOrPrivateNIC(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"192.168.1.1", true},
		{"172.16.0.5", true},
		{"8.8.8.8", true},
		{"100.64.0.1", true},
		{"127.0.0.1", false},
		{"169.254.1.1", false},
		{"0.0.0.0", false},
		{"224.0.0.1", false},
		{"::1", false},
		{"fe80::1", false},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			is := assert.New(t)
			is.Equal(tt.want, isPublicOrPrivateNIC(netip.MustParseAddr(tt.ip)))
		})
	}
}
