package client

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/cli/internal/state"
)

// A relay message may arrive over many small Read calls, ssh framing depends on it.
func TestRelayStreamRead(t *testing.T) {
	t.Parallel()

	chunk := bytes.Repeat([]byte{0xa5}, 1000)
	r := &relayStream{}
	r.pending = chunk

	buf := make([]byte, 64)
	got := make([]byte, 0, len(chunk))
	for len(got) < len(chunk) {
		n, err := r.Read(buf)
		require.NoError(t, err)
		require.Positive(t, n, "Read must not return 0, nil")
		got = append(got, buf[:n]...)
	}
	assert.Equal(t, chunk, got)
	assert.Empty(t, r.pending, "buffer must be drained exactly")
}

func TestRelayRequiresDaemon(t *testing.T) {
	t.Parallel()

	c := &Client{}
	_, err := c.Relay(t.Context(), &state.Target{Name: "prod"})
	assert.ErrorContains(t, err, "not backed by a daemon")
}
