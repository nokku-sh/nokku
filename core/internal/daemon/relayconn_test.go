package daemon

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// A daemon closes right after its last bytes, so a closed relay drains them.
func TestRelayConn_ReadDrainsAfterClose(t *testing.T) {
	for range 50 {
		relay := &Relay{toUser: make(chan []byte, relayBufferSize), closed: make(chan struct{})}
		for range relayBufferSize {
			relay.toUser <- []byte("tail")
		}
		relay.close()

		got, err := io.ReadAll(&relayConn{relay: relay})
		require.NoError(t, err)
		require.Equal(t, bytes.Repeat([]byte("tail"), relayBufferSize), got)
	}
}
