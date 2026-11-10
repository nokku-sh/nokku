package sshd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"uuid"

	"github.com/nokku-sh/nokku/daemon/internal/safe"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/daemon/internal/recording"
)

const (
	maxClientEnv = 64
	// Each queued signal costs a helper process once the command starts.
	maxPendingSignals = 8
	// How long an interactive shell gets after the hangup before it is killed.
	hangupGrace = 5 * time.Second
	// A tenth of a shell's cap, so nightly dumps can't fill a workspace.
	maxExecRecording = 5 << 20
	recordedNotice   = "nokkud: this session is recorded\r\n"
)

type session struct {
	ssh.Channel

	server  *Server
	conn    *ssh.ServerConn
	st      *connState
	reqs    <-chan *ssh.Request
	sysUser *account
	// The certificate principal auth matched, reported with the recording.
	principal string

	// Commands use ctx, so a disconnect reaps them even if requests misbehave.
	ctx    context.Context
	cancel context.CancelFunc

	env    []string
	rawCmd string
	// What the client asked for when a force-command replaced it.
	originalCmd string
	handled     bool
	subsystem   bool

	sessionID string

	agentLn   net.Listener
	agentSock string

	ptmx, tty *os.File

	rec *recording.Recorder

	exitMu sync.Mutex
	exited bool

	procMu sync.Mutex
	proc   *os.Process

	// Sent before the command started, flushed by setProc. Guarded by procMu.
	pendingSignals []string
}

// A failing recording never disturbs the stream, Recorder swallows its errors.
type recOut struct {
	w   io.Writer
	rec *recording.Recorder
}

func (s *Server) serveSession(ctx context.Context, st *connState, newCh ssh.NewChannel) {
	conn := st.conn
	ch, reqs, err := newCh.Accept()
	if err != nil {
		slog.Debug("accept session channel failed", "error", err)
		return
	}
	defer ch.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sess := &session{
		Channel:   ch,
		server:    s,
		conn:      conn,
		st:        st,
		reqs:      reqs,
		sysUser:   st.user,
		principal: st.principal,
		ctx:       ctx,
		cancel:    cancel,
		sessionID: uuid.NewV7().String(),
	}
	s.emit(sess.event(eventSessionStart))
	sess.handleRequests()
}

func (sess *session) event(typ eventType) auditEvent {
	ev := connEvent(sess.conn, typ)
	ev.SessionID = sess.sessionID
	ev.User = sess.sysUser.Name
	return ev
}

// When the request stream ends the process is killed and the handler joined.
func (sess *session) handleRequests() {
	var handlerDone chan struct{}
	startHandler := func(fn func()) {
		handlerDone = make(chan struct{})
		go safe.Func("session handler", func() {
			defer close(handlerDone)
			fn()
		})()
	}

	for req := range sess.reqs {
		switch req.Type {
		case "shell", "exec":
			if sess.handleCommand(req) {
				startHandler(sess.run)
			}
		case "subsystem":
			if sess.acceptSubsystem(req) {
				startHandler(sess.runSFTP)
			}
		case "env":
			_ = req.Reply(sess.setClientEnv(req.Payload), nil)
		case "pty-req":
			sess.ptyReq(req)
		case agentRequestType:
			if sess.agentRequest(req) {
				go safe.Func("agent forward", sess.serveAgent)()
			}
		case "window-change":
			sess.windowChange(req)
		case "signal":
			sess.signal(req)
		default:
			_ = req.Reply(false, nil)
		}
	}

	// Canceling hangs up the command and stops waiting on background output.
	sess.cancel()
	if handlerDone != nil {
		<-handlerDone
		return
	}
	// No command ever ran, so nothing else releases what pty-req opened.
	if sess.ptmx != nil {
		_ = sess.ptmx.Close()
		_ = sess.tty.Close()
	}
	sess.rec.Close()
}

func (sess *session) handleCommand(req *ssh.Request) bool {
	if sess.handled {
		_ = req.Reply(false, nil)
		return false
	}
	if req.Type == "exec" {
		var e struct{ Command string }
		if ssh.Unmarshal(req.Payload, &e) != nil {
			_ = req.Reply(false, nil)
			return false
		}
		sess.rawCmd = e.Command
	}
	// Like sshd, a force-command replaces what the client asked for.
	if fc := sess.forceCommand(); fc != "" {
		sess.originalCmd, sess.rawCmd = sess.rawCmd, fc
	}
	sess.handled = true
	_ = req.Reply(true, nil)

	ev := sess.event(eventCommand)
	ev.Command = sess.rawCmd
	ev.OriginalCommand = sess.originalCmd
	sess.server.emit(ev)
	return true
}

func (sess *session) forceCommand() string {
	return sess.conn.Permissions.Extensions["force-command"]
}

// A force-command refuses all client env, so nothing can bend the command.
func (sess *session) setClientEnv(payload []byte) bool {
	var e struct{ Name, Value string }
	if sess.handled || len(sess.env) >= maxClientEnv || sess.forceCommand() != "" ||
		ssh.Unmarshal(payload, &e) != nil || !allowedEnv(e.Name) {
		return false
	}
	sess.setEnv(e.Name, e.Value)
	return true
}

// PATH, LD_*, BASH_ENV, ENV and SSH_* could steer loading or shell startup.
func allowedEnv(name string) bool {
	switch name {
	case "TERM", "LANG", "TZ", "TERM_PROGRAM", "COLORTERM":
		return true
	}
	return strings.HasPrefix(name, "LC_")
}

func (sess *session) setEnv(key, value string) {
	kv := key + "=" + value
	for i, e := range sess.env {
		if strings.HasPrefix(e, key+"=") {
			sess.env[i] = kv
			return
		}
	}
	sess.env = append(sess.env, kv)
}

func (sess *session) acceptSubsystem(req *ssh.Request) bool {
	var r struct{ Name string }
	// A force-command takes precedence over subsystems, like sshd.
	ok := !sess.handled && sess.forceCommand() == "" &&
		ssh.Unmarshal(req.Payload, &r) == nil && r.Name == "sftp"
	sess.handled = sess.handled || ok
	sess.subsystem = ok
	_ = req.Reply(ok, nil)
	if ok {
		ev := sess.event(eventSubsystem)
		ev.Command = r.Name
		sess.server.emit(ev)
	}
	return ok
}

func (sess *session) ptyReq(req *ssh.Request) {
	var r struct {
		Term     string
		Width    uint32
		Height   uint32
		WidthPx  uint32
		HeightPx uint32
		Modes    []byte
	}
	if sess.handled || sess.ptmx != nil || !certExt(sess.conn, "permit-pty") ||
		ssh.Unmarshal(req.Payload, &r) != nil {
		_ = req.Reply(false, nil)
		return
	}
	ptmx, tty, err := openPTY()
	if err != nil {
		slog.Debug("open pty failed", "error", err)
		_ = req.Reply(false, nil)
		return
	}
	if err = setWinsize(ptmx, r.Width, r.Height); err != nil {
		_ = ptmx.Close()
		_ = tty.Close()
		_ = req.Reply(false, nil)
		return
	}
	// The client's modes shape the pty, like sshd. Failure keeps the defaults.
	if err = applyTTYModes(tty, r.Modes); err != nil {
		slog.Debug("apply tty modes failed", "error", err)
	}
	// The user has to own the pty, or opening the tty by path is denied.
	if os.Geteuid() == 0 {
		if err = tty.Chown(int(sess.sysUser.UID), -1); err != nil {
			slog.Debug("chown pty failed", "error", err)
		}
	}
	sess.ptmx, sess.tty = ptmx, tty
	// A client without TERM sends an empty one, buildEnv then sets the default.
	if r.Term != "" {
		sess.setEnv("TERM", r.Term)
	}
	sess.startRecorder(int(r.Width), int(r.Height))
	_ = req.Reply(true, nil)
}

func (sess *session) windowChange(req *ssh.Request) {
	var w struct{ Cols, Rows, W, H uint32 }
	if ssh.Unmarshal(req.Payload, &w) == nil && sess.ptmx != nil {
		if err := setWinsize(sess.ptmx, w.Cols, w.Rows); err != nil {
			slog.Debug("resize pty failed", "error", err)
		} else {
			sess.rec.RecordResize(int(w.Cols), int(w.Rows))
		}
	}
	_ = req.Reply(true, nil)
}

func (sess *session) signal(req *ssh.Request) {
	var sg struct{ Signal string }
	// Like sshd, a forced command or subsystem takes no client signals.
	if sess.forceCommand() != "" || sess.subsystem || ssh.Unmarshal(req.Payload, &sg) != nil {
		_ = req.Reply(false, nil)
		return
	}
	if _, ok := signalByName(sg.Signal); !ok {
		_ = req.Reply(false, nil)
		return
	}
	sess.procMu.Lock()
	p := sess.proc
	if p == nil && len(sess.pendingSignals) < maxPendingSignals {
		sess.pendingSignals = append(sess.pendingSignals, sg.Signal)
	}
	sess.procMu.Unlock()
	if p != nil {
		sess.signalProc(p.Pid, sg.Signal)
	}
	_ = req.Reply(true, nil)
}

// RFC 4254 section 6.10.
func (sess *session) exitSignal(name string, code int) {
	sess.finish(code, func() {
		sig := struct {
			Signal     string
			CoreDumped bool
			Message    string
			Language   string
		}{Signal: name}
		_, _ = sess.SendRequest("exit-signal", false, ssh.Marshal(sig))
	})
}

// The single teardown path for a session.
func (sess *session) finish(code int, send func()) {
	sess.exitMu.Lock()
	defer sess.exitMu.Unlock()
	if sess.exited {
		return
	}
	sess.exited = true
	sess.cancel()

	sess.rec.RecordExit(code)
	sess.rec.Close()

	ev := sess.event(eventSessionEnd)
	ev.ExitCode = code
	sess.server.emit(ev)

	send()
	_ = sess.Close()
}

func (sess *session) run() {
	if sess.ptmx != nil {
		sess.runPTY()
		return
	}
	sess.runPlain()
}

func (sess *session) runPTY() {
	defer sess.ptmx.Close()
	defer sess.tty.Close()

	cmd, notice, err := sess.startInHome(sess.shellCmd, func(cmd *exec.Cmd) error {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = sess.tty, sess.tty, sess.tty
		cmd.SysProcAttr.Setctty = true
		cmd.WaitDelay = hangupGrace
		return cmd.Start()
	})
	if err != nil {
		slog.Debug("start pty command failed", "error", err)
		sess.exit(1)
		return
	}
	sess.setProc(cmd.Process)
	// Drop our slave end, so the master reports EOF once the child exits.
	_ = sess.tty.Close()
	// A background process can hold the slave. Closing the master hangs it up.
	stop := context.AfterFunc(sess.ctx, safe.Func("close pty", func() { _ = sess.ptmx.Close() }))
	defer stop()

	// Read once, a running session keeps its rule. Only keystrokes count.
	touch := func() {}
	if idle := sess.server.access.Load().policy.IdleTimeout; idle > 0 {
		timer := time.AfterFunc(idle, safe.Func("idle timeout", sess.idleOut))
		defer timer.Stop()
		touch = func() { timer.Reset(idle) }
	}

	var input sync.WaitGroup
	input.Go(safe.Func("pty input", func() {
		buf := make([]byte, 32*1024)
		for {
			n, readErr := sess.Read(buf)
			if n > 0 {
				touch()
				// Only echoed input is recorded, so password prompts never are.
				if sess.rec != nil && echoEnabled(sess.ptmx) {
					sess.rec.RecordInput(buf[:n])
				}
				if _, writeErr := sess.ptmx.Write(buf[:n]); writeErr != nil {
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}))

	out := recOut{w: sess, rec: sess.rec}
	// nk's ssh config, ssh -q and most IDEs hide the login banner, this line shows.
	if sess.rec != nil {
		_, _ = io.WriteString(out, recordedNotice)
	}
	if notice != "" {
		_, _ = io.WriteString(out, notice+"\r\n")
	}
	_, _ = io.Copy(out, sess.ptmx)
	_ = sess.ptmx.Close()
	_ = cmd.Wait()

	// exitProcess closes the channel, which unblocks the input relay.
	sess.exitProcess(cmd.ProcessState)
	input.Wait()
}

// The chdir runs as the user. If it fails the process runs in /, like sshd.
func (sess *session) startInHome(
	build func() (*exec.Cmd, error),
	start func(*exec.Cmd) error,
) (cmd *exec.Cmd, notice string, err error) {
	if cmd, err = build(); err != nil {
		return nil, "", err
	}
	if err = start(cmd); err == nil {
		return cmd, "", nil
	}
	errno, ok := errors.AsType[syscall.Errno](err)
	if !ok {
		return nil, "", err
	}
	retry, retryErr := build()
	if retryErr != nil {
		return nil, "", err
	}
	retry.Dir = "/"
	if start(retry) != nil {
		return nil, "", err
	}
	reason := errno.Error()
	return retry, fmt.Sprintf(
		"Could not chdir to home directory %s: %s%s",
		sess.sysUser.Home, strings.ToUpper(reason[:1]), reason[1:],
	), nil
}

// Like OpenSSH, a shell gets a dash in argv[0], so the profile is read.
func (sess *session) shellCmd() (*exec.Cmd, error) {
	shell := sess.sysUser.Shell
	// #nosec G204 - running the authenticated user's shell is the whole point.
	cmd := exec.CommandContext(sess.ctx, shell)
	// A hangup lets a shell save history and run traps. WaitDelay then kills.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGHUP) }
	cmd.Args = []string{"-" + filepath.Base(shell)}
	if sess.rawCmd != "" {
		cmd.Args = []string{filepath.Base(shell), "-c", sess.rawCmd}
	}
	cmd.Dir = sess.sysUser.Home
	cmd.Env = sess.buildEnv()
	attr, err := sysProcAttr(sess.sysUser)
	if err != nil {
		return nil, err
	}
	cmd.SysProcAttr = attr
	return cmd, nil
}

func (sess *session) setProc(p *os.Process) {
	sess.procMu.Lock()
	sess.proc = p
	pending := sess.pendingSignals
	sess.pendingSignals = nil
	sess.procMu.Unlock()
	for _, name := range pending {
		sess.signalProc(p.Pid, name)
	}
}

// Like OpenSSH, exit-signal when killed, so clients surface 128+signal.
func (sess *session) exitProcess(st *os.ProcessState) {
	// The pid is reaped and may be reused, so no later signal goes to it.
	sess.procMu.Lock()
	sess.proc = nil
	sess.procMu.Unlock()

	name, code, signaled := processSignal(st)
	if !signaled {
		status := 1
		if st != nil && st.Exited() {
			status = st.ExitCode()
		}
		sess.exit(status)
		return
	}
	if name == "" {
		// Signal outside the RFC 4254 name table: still surface 128+n.
		sess.exit(code)
		return
	}
	sess.exitSignal(name, code)
}

func (sess *session) runPlain() {
	// Exec records too, it is where sensitive output leaves the machine.
	sess.startRecorder(80, 24)

	var stdin io.WriteCloser
	var stdout io.ReadCloser
	cmd, notice, err := sess.startInHome(sess.shellCmd, func(cmd *exec.Cmd) (err error) {
		// Extended data, as interleaving breaks length-prefixed protocols.
		cmd.Stderr = recOut{w: sess.Stderr(), rec: sess.rec}
		stdin, stdout, err = startPiped(cmd)
		return err
	})
	if err != nil {
		slog.Debug("start command failed", "error", err)
		sess.exit(1)
		return
	}
	if notice != "" {
		_, _ = io.WriteString(sess.Stderr(), notice+"\n")
	}
	sess.relay(cmd, stdin, stdout)
}

func (sess *session) startRecorder(width, height int) {
	if sess.rec != nil || !sess.server.access.Load().policy.Record {
		return
	}
	// The CA signs the key id, so a web recording may use the core's session
	// id. It names a file, so even a signed one must be canonical.
	recSessionID := sess.sessionID
	keyID := sess.conn.Permissions.Extensions["nokku-cert-key-id"]
	if id, ok := strings.CutPrefix(keyID, login.WebSessionKeyIDPrefix); ok && login.ValidID(id) {
		recSessionID = id
	}
	term, _ := sess.envValue("TERM")
	maxSize := sess.server.maxRecording
	if maxSize == 0 && sess.ptmx == nil {
		maxSize = maxExecRecording
	}
	rec, err := recording.New(recording.Options{
		Width:     width,
		Height:    height,
		Title:     "ssh-" + sess.sysUser.Name,
		SessionID: recSessionID,
		User:      sess.sysUser.Name,
		Principal: sess.principal,
		Term:      term,
		OnCut:     sess.recordingCut,
		MaxSize:   maxSize,
		Uploads:   sess.server.uploads,
	})
	if err != nil {
		// Fails open so a full disk can't lock admins out. The gap is audited.
		slog.Warn("session not recorded", "session_id", sess.sessionID, "error", err)
		sess.recordingDegraded("not recorded: " + err.Error())
		return
	}
	sess.rec = rec
}

func (sess *session) envValue(key string) (string, bool) {
	for _, e := range sess.env {
		if v, ok := strings.CutPrefix(e, key+"="); ok {
			return v, true
		}
	}
	return "", false
}

// A write error leaves the session running unrecorded, like a failed start.
func (sess *session) recordingCut(err error) {
	if errors.Is(err, recording.ErrSizeLimit) {
		sess.recordingFull()
		return
	}
	sess.recordingDegraded("recording stopped: " + err.Error())
}

// An interactive session ends at the limit, so a flood cannot hide what is
// typed next. An exec session runs on unrecorded, its command is in the audit
// log and transfers like git clone must not die halfway.
func (sess *session) recordingFull() {
	if sess.ptmx == nil {
		sess.recordingDegraded("size limit reached, the rest of the output is not recorded")
		return
	}
	sess.recordingDegraded("size limit reached, session ended")
	_, _ = io.WriteString(sess, "\r\nnokkud: the recording of this session is full, closing it\r\n")
	sess.exit(1)
}

func (sess *session) idleOut() {
	sess.server.emit(sess.event(eventSessionIdle))
	_, _ = io.WriteString(sess, "\r\nnokkud: no input for too long, closing this session\r\n")
	sess.exit(1)
}

func (sess *session) recordingDegraded(reason string) {
	ev := sess.event(eventRecordingDegraded)
	ev.Error = reason
	sess.server.emit(ev)
}

func (t recOut) Write(p []byte) (int, error) {
	t.rec.RecordOutput(p)
	return t.w.Write(p)
}

// A failed start closes both pipes.
func startPiped(cmd *exec.Cmd) (stdin io.WriteCloser, stdout io.ReadCloser, err error) {
	if stdin, err = cmd.StdinPipe(); err != nil {
		return nil, nil, err
	}
	if stdout, err = cmd.StdoutPipe(); err != nil {
		_ = stdin.Close()
		return nil, nil, err
	}
	// Bounds Wait if a background process holds stderr, and the hangup grace.
	cmd.WaitDelay = time.Second
	return stdin, stdout, cmd.Start()
}

func (sess *session) relay(cmd *exec.Cmd, stdin io.WriteCloser, stdout io.ReadCloser) {
	sess.setProc(cmd.Process)
	stop := context.AfterFunc(sess.ctx, safe.Func("close stdout", func() { _ = stdout.Close() }))
	defer stop()

	var relay sync.WaitGroup

	// Only output is recorded, without a pty no echo tells typed secrets apart.
	outW := recOut{w: sess, rec: sess.rec}

	relay.Go(safe.Func("stdin", func() {
		defer stdin.Close()
		_, _ = io.Copy(stdin, sess)
	}))

	stdoutDone := make(chan struct{})
	relay.Go(safe.Func("stdout", func() {
		defer close(stdoutDone)
		_, _ = io.Copy(outW, stdout)
	}))

	// Drain stdout first, cmd.Wait closes the pipe and would truncate the rest.
	<-stdoutDone
	if waitErr := cmd.Wait(); waitErr != nil {
		slog.Debug("command exited", "error", waitErr)
	}

	// exitProcess closes the channel, which unblocks the stdin relay.
	sess.exitProcess(cmd.ProcessState)
	relay.Wait()
}

func (sess *session) buildEnv() []string {
	env := cmdEnv(sess.sysUser)
	env = append(env, sess.env...)
	if sess.conn != nil {
		// bash only reads ~/.bashrc for a remote command if SSH_CLIENT is set.
		rHost, rPort := splitHostPort(sess.conn.RemoteAddr())
		lHost, lPort := splitHostPort(sess.conn.LocalAddr())
		env = append(
			env,
			"SSH_CLIENT="+rHost+" "+rPort+" "+lPort,
			"SSH_CONNECTION="+rHost+" "+rPort+" "+lHost+" "+lPort,
		)
	}
	if sess.ptmx != nil {
		env = append(env, "SSH_TTY="+sess.tty.Name())
		// Like sshd, only a pty session has a TERM.
		if _, ok := sess.envValue("TERM"); !ok {
			env = append(env, "TERM=xterm-256color")
		}
	}
	if sess.agentSock != "" {
		env = append(env, "SSH_AUTH_SOCK="+sess.agentSock)
	}
	if sess.originalCmd != "" {
		env = append(env, "SSH_ORIGINAL_COMMAND="+sess.originalCmd)
	}
	return env
}

func splitHostPort(a net.Addr) (string, string) {
	host, port, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String(), ""
	}
	return host, port
}

func exitCodeToU32(code int) uint32 {
	if code < 0 || code > 255 {
		return 1
	}
	return uint32(code)
}

// Idempotent, only the first call has an effect.
func (sess *session) exit(code int) {
	sess.finish(code, func() {
		status := struct{ Status uint32 }{exitCodeToU32(code)}
		_, _ = sess.SendRequest("exit-status", false, ssh.Marshal(status))
	})
}
