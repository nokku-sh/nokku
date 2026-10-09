package daemon

import (
	"bytes"
	"errors"
	"io"
	"net"
	"time"
)

// relayConn adapts a Relay to [net.Conn] for the SSH client.
type relayConn struct {
	relay *Relay
	// buf holds the unread tail of the last chunk. Only the transport's single reader goroutine touches it.
	buf []byte
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "relay" }
func (pipeAddr) String() string  { return "relay" }

func (c *relayConn) Read(p []byte) (int, error) {
	if len(c.buf) == 0 {
		select {
		case c.buf = <-c.relay.toUser:
		case <-c.relay.done():
			// What the daemon sent before it closed is still queued.
			select {
			case c.buf = <-c.relay.toUser:
			default:
				return 0, io.EOF
			}
		}
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *relayConn) Write(p []byte) (int, error) {
	// The SSH transport reuses its packet buffers.
	select {
	case c.relay.toDaemon <- bytes.Clone(p):
		return len(p), nil
	case <-c.relay.done():
		return 0, errors.New("relay closed")
	}
}

func (c *relayConn) Close() error {
	c.relay.close()
	return nil
}

// The SSH transport is aborted through ctx and Close, never deadlines.
func (c *relayConn) SetDeadline(time.Time) error      { return nil }
func (c *relayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *relayConn) SetWriteDeadline(time.Time) error { return nil }

func (c *relayConn) LocalAddr() net.Addr  { return pipeAddr{} }
func (c *relayConn) RemoteAddr() net.Addr { return pipeAddr{} }
