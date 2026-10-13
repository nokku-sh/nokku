package client

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

const sessionTTL = 8 * time.Hour

// A test seam, so the relay can be driven without a core.
type relayStream interface {
	Send(*nokkuv1.DaemonRelayRequest) error
	Receive() (*nokkuv1.DaemonRelayResponse, error)
}

var relayClosed = &nokkuv1.DaemonRelayRequest{
	Msg: &nokkuv1.DaemonRelayRequest_Closed{Closed: &nokkuv1.DaemonRelayClosed{}},
}

// The sshd enforces its connection cap, so relays need none.
func (c *Client) runRelay(ctx context.Context, req *nokkuv1.RelayOpen) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("relay panicked", "relay", req.GetRelayId(), "panic", r)
		}
	}()
	// Canceling ctx also ends the stream, which unblocks its Receive.
	ctx, cancel := context.WithTimeout(ctx, sessionTTL)
	defer cancel()
	stream, err := c.ctl.DaemonRelay(ctx)
	if err == nil {
		// Ready must be the first message, the core resolves its pending relay on it.
		err = stream.Send(&nokkuv1.DaemonRelayRequest{
			Msg: &nokkuv1.DaemonRelayRequest_Ready{Ready: &nokkuv1.DaemonRelayReady{RelayId: req.RelayId}},
		})
	}
	if err != nil {
		slog.Warn("relay failed", "relay", req.GetRelayId(), "error", err)
		return
	}
	slog.Info("relay connected", "relay", req.GetRelayId())
	c.srv.ServeConn(&relayConn{
		stream: stream,
		cancel: cancel,
		remote: clientAddr(req.GetClientAddr()),
		local:  net.TCPAddrFromAddrPort(c.sshAddr),
	})
	slog.Debug("relay disconnected", "relay", req.GetRelayId())
}

// Source-address options need a TCP address. One that does not parse is unspecified and matches none.
func clientAddr(addr string) net.Addr {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return net.TCPAddrFromAddrPort(ap)
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		ip = netip.IPv4Unspecified()
	}
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, 0))
}

// Its remote address is the user's, so audit events and source-address options see the user, not the relay.
type relayConn struct {
	stream relayStream
	// cancel ends the stream, which unblocks a pending Receive or Send.
	cancel        context.CancelFunc
	remote, local net.Addr

	// pending is the unread tail of the last frame. Only the ssh transport's reader touches it.
	pending []byte

	// sendMu makes Closed the last frame, the stream takes one sender at a time.
	sendMu sync.Mutex
	closed bool

	deadlineMu sync.Mutex
	deadline   *time.Timer
}

func (c *relayConn) Read(p []byte) (int, error) {
	for len(c.pending) == 0 {
		msg, err := c.stream.Receive()
		if err != nil {
			return 0, err
		}
		switch m := msg.GetMsg().(type) {
		case *nokkuv1.DaemonRelayResponse_Data:
			c.pending = m.Data
		case *nokkuv1.DaemonRelayResponse_Closed:
			return 0, io.EOF
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *relayConn) Write(p []byte) (int, error) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	// Send marshals before it returns, so the stream does not keep p.
	if err := c.stream.Send(&nokkuv1.DaemonRelayRequest{
		Msg: &nokkuv1.DaemonRelayRequest_Data{Data: p},
	}); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close skips the Closed frame while a Write is stuck on a dead core. The cancel unblocks that Write.
func (c *relayConn) Close() error {
	if c.sendMu.TryLock() {
		if !c.closed {
			c.closed = true
			_ = c.stream.Send(relayClosed)
		}
		c.sendMu.Unlock()
	}
	c.cancel()
	return c.SetDeadline(time.Time{})
}

// SetDeadline ends the connection when it passes, a stream cannot time out one read.
func (c *relayConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.deadline != nil {
		c.deadline.Stop()
		c.deadline = nil
	}
	if !t.IsZero() {
		c.deadline = time.AfterFunc(time.Until(t), c.cancel)
	}
	return nil
}

func (c *relayConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *relayConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

func (c *relayConn) RemoteAddr() net.Addr { return c.remote }
func (c *relayConn) LocalAddr() net.Addr  { return c.local }
