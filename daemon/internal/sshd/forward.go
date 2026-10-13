package sshd

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// The payload of a direct-tcpip (RFC 4254 7.2) or forwarded-tcpip (7.3) channel open.
type tcpipChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

type tcpipForwardData struct {
	BindAddr string
	BindPort uint32
}

// Each open channel and each -R listener holds a channel slot.
type connState struct {
	conn *ssh.ServerConn
	user *account
	// The certificate principal auth matched, reported with the recording.
	principal string
	channels  chan struct{}

	mu       sync.Mutex
	forwards map[string]net.Listener
}

func newConnState(conn *ssh.ServerConn, limit int) *connState {
	sysUser, _ := conn.Permissions.ExtraData[accountKey].(*account)
	return &connState{
		conn:      conn,
		user:      sysUser,
		principal: conn.Permissions.Extensions["nokku-principal"],
		channels:  make(chan struct{}, limit),
		forwards:  make(map[string]net.Listener),
	}
}

func (st *connState) acquireChannel() bool {
	select {
	case st.channels <- struct{}{}:
		return true
	default:
		return false
	}
}

func (st *connState) releaseChannel() { <-st.channels }

func (st *connState) close() {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, ln := range st.forwards {
		_ = ln.Close()
	}
	st.forwards = nil
}

func (s *Server) forwardingAllowed(conn *ssh.ServerConn) bool {
	return s.policy.Load().AllowForwarding && certExt(conn, "permit-port-forwarding")
}

func (s *Server) serveDirectTCPIP(st *connState, newCh ssh.NewChannel) {
	var d tcpipChannelData
	if err := ssh.Unmarshal(newCh.ExtraData(), &d); err != nil {
		_ = newCh.Reject(ssh.ConnectionFailed, "bad direct-tcpip request")
		return
	}
	if !s.forwardingAllowed(st.conn) {
		_ = newCh.Reject(ssh.Prohibited, "port forwarding is disabled")
		return
	}

	dest := net.JoinHostPort(d.DestAddr, strconv.FormatUint(uint64(d.DestPort), 10))
	dialer := net.Dialer{Timeout: 5 * time.Second}
	dconn, err := dialer.DialContext(context.Background(), "tcp", dest)
	if err != nil {
		slog.Debug("direct-tcpip dial failed", "addr", dest, "error", err)
		_ = newCh.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	ev := connEvent(st.conn, eventForward)
	ev.Target = dest
	s.emit(ev)

	ch, reqs, err := newCh.Accept()
	if err != nil {
		_ = dconn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	proxy(ch, dconn)
}

func (s *Server) handleGlobalRequests(st *connState, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			_ = req.Reply(s.tcpipForward(st, req.Payload))
		case "cancel-tcpip-forward":
			_ = req.Reply(s.cancelTCPIPForward(st, req.Payload), nil)
		case "keepalive@openssh.com":
			_ = req.Reply(true, nil)
		default:
			_ = req.Reply(false, nil)
		}
	}
}

func (s *Server) tcpipForward(st *connState, payload []byte) (bool, []byte) {
	var f tcpipForwardData
	if !s.forwardingAllowed(st.conn) || ssh.Unmarshal(payload, &f) != nil || f.BindPort > 65535 {
		return false, nil
	}
	// Like OpenSSH, only root may bind a privileged port. The daemon runs as root, so it checks by hand.
	if f.BindPort != 0 && f.BindPort < 1024 && st.user.UID != 0 {
		return false, nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	// A nil map means teardown. The listener holds a channel slot, or one connection could exhaust descriptors.
	if st.forwards == nil || st.forwards[forwardKey(f)] != nil || !st.acquireChannel() {
		return false, nil
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", forwardAddr(f, s.policy.Load().GatewayPorts))
	if err != nil {
		st.releaseChannel()
		return false, nil
	}
	// A port 0 forward is kept under the port it got, the client cancels it by that one.
	f.BindPort = uint32(addrPort(ln.Addr()).Port())
	st.forwards[forwardKey(f)] = ln
	ev := connEvent(st.conn, eventRemoteForward)
	ev.Target = ln.Addr().String()
	s.emit(ev)
	go s.acceptForwarded(st, ln, f.BindAddr)
	return true, ssh.Marshal(struct{ Port uint32 }{f.BindPort})
}

func (s *Server) cancelTCPIPForward(st *connState, payload []byte) bool {
	var f tcpipForwardData
	if ssh.Unmarshal(payload, &f) != nil {
		return false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	ln, ok := st.forwards[forwardKey(f)]
	if ok {
		delete(st.forwards, forwardKey(f))
		_ = ln.Close()
	}
	return ok
}

// Forwards are keyed on what the client asked for, so a policy change between -R and its cancel cannot strand one.
func forwardKey(f tcpipForwardData) string {
	return net.JoinHostPort(f.BindAddr, strconv.FormatUint(uint64(f.BindPort), 10))
}

// Loopback unless gateway ports are on, so a user cannot expose a service on the host's interfaces.
func forwardAddr(f tcpipForwardData, gateway bool) string {
	host := "127.0.0.1"
	if gateway {
		host = f.BindAddr
		if host == "" {
			host = "0.0.0.0"
		}
	}
	return net.JoinHostPort(host, strconv.FormatUint(uint64(f.BindPort), 10))
}

// bindAddr is echoed so the client matches its -R forward.
func (s *Server) acceptForwarded(st *connState, ln net.Listener, bindAddr string) {
	defer st.releaseChannel()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if !st.acquireChannel() {
			_ = c.Close()
			continue
		}
		go func() {
			defer st.releaseChannel()
			origin := addrPort(c.RemoteAddr())
			ch, reqs, openErr := st.conn.OpenChannel("forwarded-tcpip", ssh.Marshal(tcpipChannelData{
				DestAddr:   bindAddr,
				DestPort:   uint32(addrPort(ln.Addr()).Port()),
				OriginAddr: origin.Addr().String(),
				OriginPort: uint32(origin.Port()),
			}))
			if openErr != nil {
				slog.Debug("open forwarded-tcpip channel failed", "error", openErr)
				_ = c.Close()
				return
			}
			go ssh.DiscardRequests(reqs)
			proxy(ch, c)
		}()
	}
}

func proxy(ch ssh.Channel, c net.Conn) {
	closeBoth := sync.OnceFunc(func() {
		_ = ch.Close()
		_ = c.Close()
	})
	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = io.Copy(ch, c)
		closeBoth()
	})
	wg.Go(func() {
		_, _ = io.Copy(c, ch)
		closeBoth()
	})
	wg.Wait()
}

func addrPort(a net.Addr) netip.AddrPort {
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}
