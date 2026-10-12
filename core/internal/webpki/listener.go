package webpki

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"time"
)

const (
	// A TLS handshake starts with this record type, no HTTP method does.
	tlsHandshake = 0x16
	// sniffTimeout is how long a client has for its first byte, the same as for its request headers.
	sniffTimeout = 5 * time.Second
)

// sniffer answers TLS and plain HTTP on one port, the first byte of a connection tells which.
type sniffer struct {
	net.Listener

	conf  *tls.Config
	conns chan net.Conn
	errs  chan error
	done  chan struct{}
	stop  func()
}

// Listener speaks TLS on l with a client that starts a handshake, every other connection stays plain for the proxy.
func (i *Identity) Listener(l net.Listener) net.Listener {
	done := make(chan struct{})
	s := &sniffer{
		Listener: l,
		// nk, nokkud and every current browser speak TLS 1.3. The daemon streams need h2.
		conf: &tls.Config{
			MinVersion:     tls.VersionTLS13,
			GetCertificate: i.cert,
			NextProtos:     []string{"h2", "http/1.1"},
		},
		conns: make(chan net.Conn),
		errs:  make(chan error),
		done:  done,
		stop:  sync.OnceFunc(func() { close(done) }),
	}
	go s.accept()
	return s
}

func (s *sniffer) Accept() (net.Conn, error) {
	select {
	case c := <-s.conns:
		return c, nil
	case err := <-s.errs:
		return nil, err
	case <-s.done:
		return nil, net.ErrClosed
	}
}

func (s *sniffer) Close() error {
	s.stop()
	return s.Listener.Close()
}

// accept gives every connection a goroutine of its own, a client that sends nothing must not hold up the next.
func (s *sniffer) accept() {
	for {
		c, err := s.Listener.Accept()
		if err == nil {
			go s.sniff(c)
			continue
		}
		// net/http backs off on a temporary error, so it has to see this one.
		select {
		case s.errs <- err:
		case <-s.done:
			return
		}
	}
}

func (s *sniffer) sniff(c net.Conn) {
	first := make([]byte, 1)
	_ = c.SetReadDeadline(time.Now().Add(sniffTimeout))
	if _, err := io.ReadFull(c, first); err != nil {
		_ = c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	c = &peeked{Conn: c, first: first}
	if first[0] == tlsHandshake {
		c = tls.Server(c, s.conf)
	}
	select {
	case s.conns <- c:
	case <-s.done:
		_ = c.Close()
	}
}

// peeked hands the sniffed byte to whoever reads the connection next.
type peeked struct {
	net.Conn

	first []byte
}

func (p *peeked) Read(b []byte) (int, error) {
	if len(p.first) > 0 && len(b) > 0 {
		n := copy(b, p.first)
		p.first = p.first[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}
