package daemon

import (
	"bytes"
	"io"
	"testing"
)

// The daemon queues its last bytes and closes right after, so a closed relay
// must still hand them out.
func TestRelayConn_ReadDrainsAfterClose(t *testing.T) {
	for range 50 {
		relay := &Relay{toUser: make(chan []byte, relayBufferSize), closed: make(chan struct{})}
		for range relayBufferSize {
			relay.toUser <- []byte("tail")
		}
		relay.close()

		got, err := io.ReadAll(&relayConn{relay: relay})
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		if want := bytes.Repeat([]byte("tail"), relayBufferSize); !bytes.Equal(got, want) {
			t.Fatalf("read %d bytes after close, want %d", len(got), len(want))
		}
	}
}
