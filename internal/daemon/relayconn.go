package daemon

import (
	"errors"
	"io"
	"net"
	"time"
)

// NewRelayConn adapts a Relay to [net.Conn] for the SSH client. Write copies
// the caller's slice because the SSH transport reuses its packet buffers.
type relayConn struct {
	relay *Relay

	// buf holds the tail of a received chunk that was larger than the
	// caller's read buffer. Only the transport's single reader goroutine
	// touches it.
	buf []byte
}

// pipeAddr stands in for a network address: relays have no endpoint.
type pipeAddr struct{}

func (pipeAddr) Network() string { return "relay" }
func (pipeAddr) String() string  { return "relay" }

func NewRelayConn(relay *Relay) net.Conn { return &relayConn{relay: relay} }

func (c *relayConn) Read(p []byte) (int, error) {
	if len(c.buf) == 0 {
		select {
		case c.buf = <-c.relay.ToUser:
		case <-c.relay.Done():
			return 0, io.EOF
		}
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *relayConn) Write(p []byte) (int, error) {
	chunk := make([]byte, len(p))
	copy(chunk, p)
	select {
	case c.relay.ToDaemon <- chunk:
		return len(p), nil
	case <-c.relay.Done():
		return 0, errors.New("relay closed")
	}
}

func (c *relayConn) Close() error {
	c.relay.Close()
	return nil
}

// Deadlines have nothing to arm: the SSH transport is aborted through
// context cancellation and Close, never through timeouts.
func (c *relayConn) SetDeadline(time.Time) error      { return nil }
func (c *relayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *relayConn) SetWriteDeadline(time.Time) error { return nil }

func (c *relayConn) LocalAddr() net.Addr  { return pipeAddr{} }
func (c *relayConn) RemoteAddr() net.Addr { return pipeAddr{} }
