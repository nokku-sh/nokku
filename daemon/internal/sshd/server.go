package sshd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"uuid"

	"golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/daemon/internal/recording"
	"github.com/nokku-sh/nokku/daemon/internal/report"
	"github.com/nokku-sh/nokku/daemon/internal/safe"
	"github.com/nokku-sh/nokku/daemon/internal/state"
)

const (
	// Logged-in connections. A peer that has not logged in holds none of them.
	maxConns = 100
	// At most half the slots, so the relay cannot crowd out direct logins.
	maxRelayedConns = maxConns / 2
	// One person or service account, over all its accounts here. Nobody takes every slot alone.
	maxSubjectConns = maxConns / 4
	// Like sshd's MaxStartups 10:30:60. From the start on a new unauthenticated connection is refused at random,
	// more often the fuller it gets, so whoever holds the slots cannot keep everyone else out for certain.
	startupsStart = 10
	startupsRate  = 30
	startupsFull  = 60
	// Loopback is one address for every client of a local proxy, so it has a budget of its own.
	maxLocalStartups = 10
	// One remote address cannot hold every pre-auth slot.
	maxSourceStartups = 3
	// Per connection, sessions and forwards alike.
	maxChannels = 50
	// Covers the account lookup, which may wait on a slow directory.
	handshakeTimeout = 30 * time.Second
	// Three unanswered intervals drop the client, like OpenSSH.
	aliveInterval = time.Minute
	// Under fd exhaustion the accept loop would spin a core and flood the log.
	acceptBackoff = 10 * time.Millisecond
)

var (
	errBusy  = errors.New("too many unauthenticated connections")
	errFull  = errors.New("sshd: no free connection")
	errShare = errors.New("sshd: too many connections of one subject")
)

// defaultPolicy also fills any field the core leaves unset.
var defaultPolicy = policy{Record: true, AllowForwarding: true, AllowAgentForwarding: true}

// policy is set by the core and applies to new sessions without a restart.
type policy struct {
	Record               bool
	AllowForwarding      bool
	AllowAgentForwarding bool
	// GatewayPorts lets -R forwards bind non-loopback addresses.
	GatewayPorts bool
	// IdleTimeout ends an interactive session without input. Zero never does.
	IdleTimeout time.Duration
}

type Server struct {
	// log gets the audit events. Tests point it at a buffer.
	log     *slog.Logger
	uploads *recording.Uploads
	// reports takes the open and the close of every connection for the core's audit log. Nil reports nothing.
	reports *report.Spool
	access  atomic.Pointer[access]
	// Tests point it away from /etc/nologin.
	nologinFile string
	// Tests swap the lookup to shape the account.
	lookupAccount func(name string) (*account, error)

	// Limits live on the server so tests can shrink them.
	conns         chan struct{}
	relayed       chan struct{}
	localStartups chan struct{}
	startupsStart int
	startupsFull  int
	maxSubject    int
	maxChannels   int
	aliveInterval time.Duration
	maxRecording  int64

	startupMu      sync.Mutex
	startups       int
	sourceStartups map[netip.Addr]int

	liveMu sync.Mutex
	live   map[*ssh.ServerConn]struct{}

	subjectMu    sync.Mutex
	subjectConns map[string]int

	hostKey ssh.Signer

	mu  sync.RWMutex
	cfg *ssh.ServerConfig
}

// New trusts no CA. Every login is refused until SetAccess.
func New(uploads *recording.Uploads, reports *report.Spool) (*Server, error) {
	s := &Server{
		log:            slog.Default(),
		uploads:        uploads,
		reports:        reports,
		nologinFile:    nologinPath,
		lookupAccount:  lookupAccount,
		conns:          make(chan struct{}, maxConns),
		relayed:        make(chan struct{}, maxRelayedConns),
		localStartups:  make(chan struct{}, maxLocalStartups),
		startupsStart:  startupsStart,
		startupsFull:   startupsFull,
		maxSubject:     maxSubjectConns,
		subjectConns:   map[string]int{},
		sourceStartups: map[netip.Addr]int{},
		live:           map[*ssh.ServerConn]struct{}{},
		maxChannels:    maxChannels,
		aliveInterval:  aliveInterval,
	}
	s.SetAccess(&state.Access{})
	var err error
	if s.hostKey, err = loadHostKey(); err != nil {
		return nil, err
	}
	s.Reload()
	return s, nil
}

func policyFrom(cfg *nokkuv1.DaemonConfig) policy {
	p := defaultPolicy
	if cfg == nil {
		return p
	}
	// The raw pointers carry presence, getters would flatten unset to false.
	set := func(dst *bool, v *bool) {
		if v != nil {
			*dst = *v
		}
	}
	set(&p.Record, cfg.RecordSessions)                     //nolint:protogetter // presence check
	set(&p.AllowForwarding, cfg.AllowForwarding)           //nolint:protogetter // presence check
	set(&p.AllowAgentForwarding, cfg.AllowAgentForwarding) //nolint:protogetter // presence check
	set(&p.GatewayPorts, cfg.GatewayPorts)                 //nolint:protogetter // presence check
	p.IdleTimeout = cfg.GetIdleTimeout().AsDuration()
	return p
}

// Reload rereads the host cert. Open connections keep the old one.
func (s *Server) Reload() {
	// Library defaults still offer SHA-1 kex, hmac-sha1-96, ssh-rsa, ssh-dss.
	algos := ssh.SupportedAlgorithms()
	cfg := &ssh.ServerConfig{
		KeyExchanges: algos.KeyExchanges, MACs: algos.MACs,
		PublicKeyAuthAlgorithms: algos.PublicKeyAuths,
		PublicKeyCallback:       s.publicKeyCallback,
		BannerCallback:          s.banner,
		ServerVersion:           "SSH-2.0-nokkud",
	}
	cfg.AddHostKey(withHostCert(s.hostKey))

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
}

// Idle is true with no connection past its handshake, so a port scan can't hold
// off a restart.
func (s *Server) Idle() bool {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	return len(s.live) == 0
}

// Serve returns once ctx is done and every connection and session is gone.
func (s *Server) Serve(ctx context.Context, l net.Listener) {
	stop := context.AfterFunc(ctx, safe.Func("close listener", func() { _ = l.Close() }))
	defer stop()
	var conns sync.WaitGroup
	defer conns.Wait()

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
		conns.Go(safe.Func("connection", func() { s.handleConn(ctx, nc, false) }))
	}
}

// ServeConn takes no pre-auth slot, the core already authenticated the user.
func (s *Server) ServeConn(ctx context.Context, nc net.Conn) {
	select {
	case s.relayed <- struct{}{}:
	default:
		slog.Warn("dropping relayed connection, the relay slots are full", "remote", nc.RemoteAddr())
		_ = nc.Close()
		return
	}
	defer func() { <-s.relayed }()
	s.handleConn(ctx, nc, true)
}

// DropRevoked ends open sessions on a revoke, SetAccess only gates new logins.
func (s *Server) DropRevoked() {
	a := s.access.Load()
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	for conn := range s.live {
		ext := conn.Permissions.Extensions
		if slices.Contains(a.principals[conn.User()], ext["nokku-principal"]) && a.trusts(ext["nokku-ca"]) {
			continue
		}
		slog.Info("closing connection, access was revoked", "user", conn.User(), "remote", conn.RemoteAddr())
		_ = conn.Close()
	}
}

// ctx closes the connection, which ends its sessions like a client hanging up.
func (s *Server) handleConn(ctx context.Context, nc net.Conn, relayed bool) {
	defer nc.Close()
	stop := context.AfterFunc(ctx, safe.Func("close connection", func() { _ = nc.Close() }))
	defer stop()

	conn, chans, reqs, leave, err := s.handshake(nc, relayed)
	if errors.Is(err, errBusy) {
		slog.Warn("dropping connection", "remote", nc.RemoteAddr(), "error", err)
		return
	}
	if err != nil {
		slog.Debug("handshake failed", "remote", nc.RemoteAddr(), "error", err)
		return
	}
	defer leave()
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
	// Deferred first, so the close is reported once every session of the connection ended.
	id := uuid.NewV7().String()
	s.report(conn, id, relayed, false)
	defer s.report(conn, id, relayed, true)
	// A sync that ran during the handshake could not see this connection yet.
	s.DropRevoked()

	st := newConnState(conn, s.maxChannels)
	defer st.close()
	done := make(chan struct{})
	defer close(done)
	go safe.Func("keepalive", func() { s.keepAlive(conn, done) })()
	// Canceled before the wait, so a closed connection ends all its sessions.
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	go safe.Func("global request", func() { s.handleGlobalRequests(ctx, st, reqs) })()
	for newCh := range chans {
		var serve func(context.Context, *connState, ssh.NewChannel)
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
		wg.Go(safe.Func(newCh.ChannelType(), func() {
			defer st.releaseChannel()
			serve(ctx, st, newCh)
		}))
	}
}

func (s *Server) report(conn *ssh.ServerConn, id string, relayed, closed bool) {
	if s.reports == nil {
		return
	}
	s.reports.Add(report.Event{
		ConnectionID: id,
		Closed:       closed,
		Time:         time.Now(),
		Principal:    conn.Permissions.Extensions["nokku-principal"],
		KeyID:        conn.Permissions.Extensions["nokku-cert-key-id"],
		Remote:       conn.RemoteAddr().String(),
		Client:       string(conn.ClientVersion()),
		Relayed:      relayed,
	})
}

// handshake returns leave, which gives back the slot the login took.
func (s *Server) handshake(
	nc net.Conn,
	relayed bool,
) (conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, leave func(), err error) {
	if !relayed {
		release, ok := s.acquireStartup(nc.RemoteAddr())
		if !ok {
			return nil, nil, nil, nil, errBusy
		}
		defer release()
	}
	if err = nc.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return nil, nil, nil, nil, err
	}
	s.mu.RLock()
	cfg := *s.cfg
	s.mu.RUnlock()
	// Per connection, so the slot a login takes is given back with this connection and no other.
	cfg.VerifiedPublicKeyCallback = func(
		meta ssh.ConnMetadata, _ ssh.PublicKey, perms *ssh.Permissions, _ string,
	) (*ssh.Permissions, error) {
		var loginErr error
		leave, loginErr = s.login(meta, perms)
		return perms, loginErr
	}
	conn, chans, reqs, err = ssh.NewServerConn(nc, &cfg)
	if err == nil {
		err = nc.SetDeadline(time.Time{})
	}
	if err != nil {
		if leave != nil {
			leave()
		}
		return nil, nil, nil, nil, err
	}
	return conn, chans, reqs, leave, nil
}

// admit gives a login one of the connection slots, or tells the client why not. The share is per subject, the
// person or service account in the principal, so a team that logs in as root is not one user.
func (s *Server) admit(principal string) (leave func(), err error) {
	subject := principal
	if parts, ok := login.ParsePrincipal(principal); ok {
		subject = parts.SubjectID
	}
	s.subjectMu.Lock()
	defer s.subjectMu.Unlock()
	if s.subjectConns[subject] >= s.maxSubject {
		return nil, &ssh.BannerError{
			Err:     errShare,
			Message: fmt.Sprintf("You have %d connections open on this server, close one first.\r\n", s.maxSubject),
		}
	}
	select {
	case s.conns <- struct{}{}:
	default:
		return nil, &ssh.BannerError{
			Err:     errFull,
			Message: "This server has no free connection, try again in a moment.\r\n",
		}
	}
	s.subjectConns[subject]++
	return func() {
		<-s.conns
		s.subjectMu.Lock()
		defer s.subjectMu.Unlock()
		if s.subjectConns[subject]--; s.subjectConns[subject] == 0 {
			delete(s.subjectConns, subject)
		}
	}, nil
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
	if s.sourceStartups[source] >= maxSourceStartups || s.dropEarly() {
		return nil, false
	}
	s.startups++
	s.sourceStartups[source]++
	return func() {
		s.startupMu.Lock()
		defer s.startupMu.Unlock()
		s.startups--
		if s.sourceStartups[source]--; s.sourceStartups[source] == 0 {
			delete(s.sourceStartups, source)
		}
	}, true
}

// dropEarly refuses for certain once full, and at random from the start on. Needs startupMu.
func (s *Server) dropEarly() bool {
	if s.startups < s.startupsStart {
		return false
	}
	if s.startups >= s.startupsFull {
		return true
	}
	odds := startupsRate + (100-startupsRate)*(s.startups-s.startupsStart)/(s.startupsFull-s.startupsStart)
	return rand.IntN(100) < odds //nolint:gosec // picks which peer to drop, guards no secret
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
		kill := time.AfterFunc(3*s.aliveInterval, safe.Func("keepalive timeout", func() { _ = conn.Close() }))
		_, _, err := conn.SendRequest("keepalive@openssh.com", true, nil)
		kill.Stop()
		if err != nil {
			return
		}
	}
}

func (s *Server) banner(ssh.ConnMetadata) string {
	a := s.access.Load()
	if a.stale() {
		return staleNotice
	}
	if !a.policy.Record {
		return ""
	}
	return "This session is recorded and audited.\r\n"
}
