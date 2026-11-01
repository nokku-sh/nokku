package cmd

import (
	"testing"

	connectrpc "connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
)

func TestNoCertificatePointsAtWhatHelps(t *testing.T) {
	offline := noCertificate("web-1", connectrpc.NewError(connectrpc.CodeUnavailable, "dial tcp: refused"))
	assert.NotContains(t, offline.Error(), "nk login", "nk login can't work while the core is out of reach")
	assert.Contains(t, offline.Error(), "can't be reached")

	expired := noCertificate("web-1", connectrpc.NewError(connectrpc.CodeUnauthenticated, "session expired"))
	assert.Contains(t, expired.Error(), "run nk login")
}
