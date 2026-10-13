package sshd

import (
	"cmp"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

const (
	maxConns    = 100
	maxStartups = 10
	// One remote address cannot hold every pre-auth slot.
	maxSourceStartups = 3
	// Per connection, sessions and forwards alike.
	maxChannels = 50
	// Covers the account lookup too, which may wait on a slow directory. OpenSSH allows 120s.
	handshakeTimeout = 30 * time.Second
	// A probe left unanswered for three intervals drops the client, like OpenSSH.
	aliveInterval = time.Minute
	// Under fd exhaustion the accept loop would otherwise spin a core and flood the log.
	acceptBackoff = 10 * time.Millisecond
)

var errBusy = errors.New("too many unauthenticated connections")

// Policy is the backend-controlled part of the config. It applies to new sessions without a restart.
type Policy struct {
	Record               bool
	AllowForwarding      bool
	AllowAgentForwarding bool
	// GatewayPorts lets -R forwards bind non-loopback addresses.
	GatewayPorts bool
}

// DefaultPolicy also fills any field the backend leaves unset.
var DefaultPolicy = Policy{Record: true, AllowForwarding: true, AllowAgentForwarding: true}

// RecordingSink gets a ctx that outlives the session teardown.
type RecordingSink func(ctx context.Context, sessionID, username, principal string) io.WriteCloser

type Options struct {
	// Principals are compared as whole strings.
	Principals func(username string) []string
	// Log gets the audit events. Nil means the default logger.
	Log           *slog.Logger
	Policy        Policy
	RecordingSink RecordingSink
}

type Server struct {
	principals    func(username string) []string
	log           *slog.Logger
	recordingSink RecordingSink
	// Tests point it away from /etc/nologin.
	nologinFile string
	policy      atomic.Pointer[Policy]
	// Tests swap the lookup to shape the account.
	lookupAccount func(name string) (*account, error)

	// Limits live on the server so tests can shrink them.
	conns chan struct{}
	// Loopback has its own pre-auth budget, a local proxy puts every client behind that one address.
	startups      chan struct{}
	localStartups chan struct{}
	maxChannels   int
	aliveInterval time.Duration
	maxRecording  int64

	startupMu      sync.Mutex
	sourceStartups map[netip.Addr]int

	liveMu sync.Mutex
	live   map[*ssh.ServerConn]struct{}

	// The host key stays open while the server runs, a connection signs with it again on every rekey.
	hostKey    ssh.Signer
	hostKeyDev io.Closer

	mu         sync.RWMutex
	cfg        *ssh.ServerConfig
	trustedCAs map[string]struct{}
	retiredCAs map[string]time.Time
}

// New trusts no CA. Those come from SetTrust, and until then every login is refused.
func New(opts Options) (*Server, error) {
	if opts.Principals == nil {
		return nil, errors.New("sshd: Principals is required")
	}
	s := &Server{
		principals:     opts.Principals,
		log:            cmp.Or(opts.Log, slog.Default()),
		recordingSink:  opts.RecordingSink,
		nologinFile:    nologinPath,
		lookupAccount:  lookupAccount,
		conns:          make(chan struct{}, maxConns),
		startups:       make(chan struct{}, maxStartups),
		localStartups:  make(chan struct{}, maxStartups),
		sourceStartups: map[netip.Addr]int{},
		live:           map[*ssh.ServerConn]struct{}{},
		maxChannels:    maxChannels,
		aliveInterval:  aliveInterval,
	}
	s.policy.Store(&opts.Policy)
	var err error
	if s.hostKey, s.hostKeyDev, err = loadHostKey(); err != nil {
		return nil, err
	}
	s.Reload()
	return s, nil
}

func PolicyFrom(cfg *nokkuv1.DaemonConfig) Policy {
	p := DefaultPolicy
	if cfg == nil {
		return p
	}
	// The raw pointers carry presence, the getters would flatten unset to false.
	set := func(dst *bool, v *bool) {
		if v != nil {
			*dst = *v
		}
	}
	set(&p.Record, cfg.RecordSessions)                     //nolint:protogetter // presence check
	set(&p.AllowForwarding, cfg.AllowForwarding)           //nolint:protogetter // presence check
	set(&p.AllowAgentForwarding, cfg.AllowAgentForwarding) //nolint:protogetter // presence check
	set(&p.GatewayPorts, cfg.GatewayPorts)                 //nolint:protogetter // presence check
	return p
}

func (s *Server) SetPolicy(p Policy) {
	s.policy.Store(&p)
}

// Reload rereads the host certificate. Established connections keep the one they handshook with.
func (s *Server) Reload() {
	// The library defaults still offer SHA-1 key exchange, hmac-sha1-96, ssh-rsa and ssh-dss. OpenSSH dropped them.
	algos := ssh.SupportedAlgorithms()
	cfg := &ssh.ServerConfig{
		KeyExchanges: algos.KeyExchanges, MACs: algos.MACs,
		PublicKeyAuthAlgorithms:   algos.PublicKeyAuths,
		PublicKeyCallback:         s.publicKeyCallback,
		VerifiedPublicKeyCallback: s.verifiedPublicKey,
		BannerCallback:            s.banner,
		ServerVersion:             "SSH-2.0-nokkud",
	}
	cfg.AddHostKey(withHostCert(s.hostKey))

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
}

// Serve leaves established sessions to die with the process.
func (s *Server) Serve(ctx context.Context, l net.Listener) {
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	defer s.hostKeyDev.Close()

	var delay time.Duration
	for {
		nc, err := l.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			delay = min(2*delay+acceptBackoff, time.Second)
			slog.Error("accept failed", "error", err, "retry_in", delay)
			time.Sleep(delay)
			continue
		}
		delay = 0

		select {
		case s.conns <- struct{}{}:
		default:
			slog.Warn("dropping connection, at capacity", "remote", nc.RemoteAddr())
			_ = nc.Close()
			continue
		}
		go func() {
			defer func() { <-s.conns }()
			s.handleConn(nc, false)
		}()
	}
}

// ServeConn takes no pre-auth slot, the backend already authenticated the user. The connection cap still counts.
func (s *Server) ServeConn(nc net.Conn) {
	select {
	case s.conns <- struct{}{}:
	default:
		slog.Warn("dropping relayed connection, at capacity", "remote", nc.RemoteAddr())
		_ = nc.Close()
		return
	}
	defer func() { <-s.conns }()
	s.handleConn(nc, true)
}

// DropRevoked makes a revoke end open sessions too. Principals and CA trust only gate new logins.
func (s *Server) DropRevoked() {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	for conn := range s.live {
		ext := conn.Permissions.Extensions
		if slices.Contains(s.principals(conn.User()), ext["nokku-principal"]) && s.trustedCAWire(ext["nokku-ca"]) {
			continue
		}
		slog.Info("closing connection, access was revoked", "user", conn.User(), "remote", conn.RemoteAddr())
		_ = conn.Close()
	}
}

func (s *Server) handleConn(nc net.Conn, relayed bool) {
	defer nc.Close()
	defer recoverPanic("connection")

	conn, chans, reqs, err := s.handshake(nc, relayed)
	if errors.Is(err, errBusy) {
		slog.Warn("dropping connection", "remote", nc.RemoteAddr(), "error", err)
		return
	}
	if err != nil {
		slog.Debug("handshake failed", "remote", nc.RemoteAddr(), "error", err)
		return
	}
	defer conn.Close()
	s.liveMu.Lock()
	s.live[conn] = struct{}{}
	s.liveMu.Unlock()
	defer func() {
		s.liveMu.Lock()
		delete(s.live, conn)
		s.liveMu.Unlock()
	}()
	slog.Info("connection established",
		"user", conn.User(), "remote", conn.RemoteAddr(), "client", string(conn.ClientVersion()))
	// A sync that ran during the handshake could not see this connection yet.
	s.DropRevoked()

	st := newConnState(conn, s.maxChannels)
	defer st.close()
	done := make(chan struct{})
	defer close(done)
	go s.keepAlive(conn, done)
	go s.handleGlobalRequests(st, reqs)

	var wg sync.WaitGroup
	defer wg.Wait()
	for newCh := range chans {
		var serve func(*connState, ssh.NewChannel)
		switch newCh.ChannelType() {
		case "session":
			serve = s.serveSession
		case "direct-tcpip":
			serve = s.serveDirectTCPIP
		default:
			_ = newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		if !st.acquireChannel() {
			_ = newCh.Reject(ssh.ResourceShortage, "too many channels")
			continue
		}
		wg.Go(func() {
			defer st.releaseChannel()
			defer recoverPanic(newCh.ChannelType())
			serve(st, newCh)
		})
	}
}

// A pre-auth slot is held only while the handshake runs. A relayed connection takes none.
func (s *Server) handshake(
	nc net.Conn,
	relayed bool,
) (*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	if !relayed {
		release, ok := s.acquireStartup(nc.RemoteAddr())
		if !ok {
			return nil, nil, nil, errBusy
		}
		defer release()
	}
	if err := nc.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return nil, nil, nil, err
	}
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	return conn, chans, reqs, nc.SetDeadline(time.Time{})
}

// IPv6 peers count per /64.
func (s *Server) acquireStartup(addr net.Addr) (release func(), ok bool) {
	var source netip.Addr
	if ap, err := netip.ParseAddrPort(addr.String()); err == nil {
		source = ap.Addr().Unmap()
	}
	if source.IsLoopback() {
		select {
		case s.localStartups <- struct{}{}:
			return func() { <-s.localStartups }, true
		default:
			return nil, false
		}
	}
	if source.Is6() {
		source = netip.PrefixFrom(source, 64).Masked().Addr()
	}

	s.startupMu.Lock()
	defer s.startupMu.Unlock()
	if s.sourceStartups[source] >= maxSourceStartups {
		return nil, false
	}
	select {
	case s.startups <- struct{}{}:
	default:
		return nil, false
	}
	s.sourceStartups[source]++
	return func() {
		<-s.startups
		s.startupMu.Lock()
		defer s.startupMu.Unlock()
		if s.sourceStartups[source]--; s.sourceStartups[source] == 0 {
			delete(s.sourceStartups, source)
		}
	}, true
}

func (s *Server) keepAlive(conn *ssh.ServerConn, done <-chan struct{}) {
	t := time.NewTicker(s.aliveInterval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
		}
		kill := time.AfterFunc(3*s.aliveInterval, func() { _ = conn.Close() })
		_, _, err := conn.SendRequest("keepalive@openssh.com", true, nil)
		kill.Stop()
		if err != nil {
			return
		}
	}
}

func (s *Server) banner(ssh.ConnMetadata) string {
	if !s.policy.Load().Record {
		return ""
	}
	return "This session is recorded and audited.\r\n"
}

// Keeps one bad connection or channel from killing the daemon.
func recoverPanic(where string) {
	if r := recover(); r != nil {
		slog.Error("recovered panic", "where", where, "panic", r, "stack", string(debug.Stack()))
	}
}
