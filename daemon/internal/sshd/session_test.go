package sshd

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

func TestRecoverPanic(t *testing.T) {
	assert.NotPanics(t, func() {
		defer recoverPanic("test")
		panic("handler panic must be contained")
	})
}

func TestServerDisconnectReapsCommand(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()

	must.NoError(sess.Start("sleep 30"), "start")

	// Drop the connection mid-command. The server must kill the child and return promptly.
	done := make(chan struct{})
	go func() {
		_ = client.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("client close hung; server likely failed to reap the command")
	}
}

// A dropped client hangs up the shell like a closed terminal, so it can save its history and run its traps.
func TestServerDisconnectHangsUpTheShell(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()
	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	require.NoError(t, err, "dial")
	sess, err := client.NewSession()
	require.NoError(t, err, "new session")
	stdout, err := sess.StdoutPipe()
	require.NoError(t, err, "stdout")

	mark := filepath.Join(t.TempDir(), "hup")
	require.NoError(t, sess.Start("trap 'echo hup > "+mark+"; kill $!; exit 0' HUP; echo ready; sleep 30 & wait"))
	line := make([]byte, len("ready\n"))
	_, err = io.ReadFull(stdout, line)
	require.NoError(t, err, "the trap is set once ready is out")

	_ = client.Close()
	assert.Eventually(t, func() bool {
		_, statErr := os.Stat(mark)
		return statErr == nil
	}, 5*time.Second, 20*time.Millisecond, "the shell got no SIGHUP")
}

func TestServerSignalForwards(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()

	must.NoError(sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{}), "request pty")
	must.NoError(sess.Start("sleep 30"), "start")

	must.NoError(sess.Signal(ssh.SIGTERM), "signal")

	done := make(chan error, 1)
	go func() {
		done <- sess.Wait()
	}()
	select {
	case err = <-done:
		must.Error(err, "expected non-zero exit after signal")
	case <-time.After(5 * time.Second):
		t.Fatal("process did not terminate after signal")
	}
}

func TestServerWindowChange(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()

	must.NoError(sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{}), "request pty")

	// stty size prints "rows cols". Window change must land before exec.
	must.NoError(sess.WindowChange(40, 20), "window change")
	out, err := sess.Output("stty size")
	must.NoError(err, "exec stty")
	is.Equal("40 20", strings.TrimSpace(string(out)))
}

func TestServerEnvWhitelist(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()

	_ = sess.Setenv("LANG", "de_DE.UTF-8")
	_ = sess.Setenv("LC_MESSAGES", "fr_FR.UTF-8")
	_ = sess.Setenv("BASH_ENV", "boom")
	_ = sess.Setenv("LD_PRELOAD", "/tmp/lib.so")
	_ = sess.Setenv("SSH_AUTH_SOCK", "/tmp/evil.sock")

	out, err := sess.Output(
		`printf '%s|%s|%s|%s|%s' "$LANG" "$LC_MESSAGES" "$BASH_ENV" "$LD_PRELOAD" "$SSH_AUTH_SOCK"`,
	)
	must.NoError(err, "exec")
	fields := strings.Split(string(out), "|")
	must.Len(fields, 5, "env output = %q", out)
	// LANG and LC_MESSAGES pass through. BASH_ENV and LD_PRELOAD are refused.
	is.Equal("de_DE.UTF-8", fields[0])
	is.Equal("fr_FR.UTF-8", fields[1])
	is.Empty(fields[2])
	is.Empty(fields[3])
	// Not the client-injected value. It may still inherit the daemon's own agent socket.
	is.NotEqual("/tmp/evil.sock", fields[4])
}

// Even whitelisted client variables are refused, so an injected BASH_ENV cannot bend a restricted command.
func TestServerForceCommandBlocksEnv(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	cert := func(c *ssh.Certificate) {
		c.CriticalOptions = map[string]string{"force-command": `printf 'force:%s' "$BASH_ENV"`}
	}
	client, err := dial(t, addr, currentUser(t), userCertOpts(t, ca, cert, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()

	_ = sess.Setenv("BASH_ENV", "boom")
	_ = sess.Setenv("LC_MESSAGES", "fr_FR.UTF-8")

	out, err := sess.Output("echo this-should-be-ignored")
	must.NoError(err, "exec")
	is.Equal("force:", string(out))
}

// captureSink lets tests assert what the daemon would have uploaded.
type captureSink struct {
	mu      sync.Mutex
	data    bytes.Buffer
	closed  chan struct{}
	closeDo sync.Once
}

func (s *captureSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Write(p)
}

func (s *captureSink) Close() error {
	s.closeDo.Do(func() { close(s.closed) })
	return nil
}

func TestPlainSessionRecorded(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	dir := t.TempDir()
	t.Setenv("NOKKUD_DATA_DIR", dir)
	must.NoError(paths.Verify(), "verify paths")

	sink := &captureSink{closed: make(chan struct{})}
	factory := func(context.Context, string, string, string) io.WriteCloser { return sink }

	cur := currentUser(t)
	ca := newTestCA(t)
	principals := func(username string) []string {
		if username == cur {
			return []string{testPrincipal}
		}
		return nil
	}
	srv, err := New(Options{
		Principals:    principals,
		Policy:        Policy{Record: true},
		RecordingSink: factory,
	})
	must.NoError(err, "new server")
	srv.SetTrust(string(ssh.MarshalAuthorizedKey(ca.pub)), nil)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must.NoError(err, "listen")
	defer func() { _ = l.Close() }()
	go srv.Serve(t.Context(), l)

	client, err := dial(t, l.Addr().String(), cur, userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	must.NoError(err, "stdin pipe")
	stdout, err := sess.StdoutPipe()
	must.NoError(err, "stdout pipe")

	must.NoError(sess.Start("cat; echo on-stderr >&2"), "start")
	_, err = io.WriteString(stdin, "piped-input\n")
	must.NoError(err)
	must.NoError(stdin.Close())

	out, err := io.ReadAll(stdout)
	must.NoError(err, "read stdout")
	must.NoError(sess.Wait(), "wait")
	is.Equal("piped-input\n", string(out))

	// finish closes the recorder before the exit status is sent, so the sink is complete once Wait returns.
	select {
	case <-sink.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("recording sink was never closed")
	}

	gr, err := gzip.NewReader(&sink.data)
	must.NoError(err, "sink data is not gzip")
	cast, err := io.ReadAll(gr)
	must.NoError(err, "read recording")
	is.Contains(string(cast), `"o"`, "plain sessions must still record output")
	is.Contains(string(cast), "on-stderr", "stderr leaves the machine too, so it is recorded")
	is.NotContains(string(cast), `"i"`, "plain sessions must not record stdin")
}

// /etc/nologin refuses the login itself, so it stops forwards as well as sessions.
func TestLoginDeniedByNologin(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, where /etc/nologin does not apply")
	}
	must := require.New(t)

	nologin := filepath.Join(t.TempDir(), "nologin")
	must.NoError(os.WriteFile(nologin, []byte("maintenance\n"), 0o644))

	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{Policy: Policy{AllowForwarding: true}}, func(s *Server) {
		s.nologinFile = nologin
	})
	defer closeFn()
	echo := testEchoServer(t)
	defer echo.Close()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	if err == nil {
		defer client.Close()
		conn, dialErr := client.Dial("tcp", echo.Addr().String())
		if dialErr == nil {
			_ = conn.Close()
		}
		must.Error(dialErr, "a forward opened while /etc/nologin was present")
	}
	must.Error(err, "login succeeded while /etc/nologin was present")
}

// A direct login must not label its recording with another session's id, only a web terminal cert may.
func TestRecordingCorrelatesWebSessionID(t *testing.T) {
	const webSessionID = "0197a3f2-7c1b-7de1-9a2b-3f4c5d6e7f80"

	cases := []struct {
		name         string
		keyID        string
		wantPromoted bool
	}{
		{"web session", "nokku:web:session:" + webSessionID, true},
		{"direct login", "nokku:login:user:" + testPrincipal, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := assert.New(t)
			must := require.New(t)
			t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
			must.NoError(paths.Verify(), "verify paths")

			var mu sync.Mutex
			var gotID string
			sink := &captureSink{closed: make(chan struct{})}
			factory := func(_ context.Context, sessionID, _, _ string) io.WriteCloser {
				mu.Lock()
				gotID = sessionID
				mu.Unlock()
				return sink
			}

			cur := currentUser(t)
			ca := newTestCA(t)
			principals := func(username string) []string {
				if username == cur {
					return []string{testPrincipal}
				}
				return nil
			}
			srv, err := New(Options{
				Principals:    principals,
				Policy:        Policy{Record: true},
				RecordingSink: factory,
			})
			must.NoError(err, "new server")
			srv.SetTrust(string(ssh.MarshalAuthorizedKey(ca.pub)), nil)
			l, err := net.Listen("tcp", "127.0.0.1:0")
			must.NoError(err, "listen")
			defer func() { _ = l.Close() }()
			go srv.Serve(t.Context(), l)

			auth := userCertOpts(t, ca, func(c *ssh.Certificate) {
				c.KeyId = tc.keyID
			}, testPrincipal)
			client, err := dial(t, l.Addr().String(), cur, auth)
			must.NoError(err, "dial")
			defer client.Close()

			sess, err := client.NewSession()
			must.NoError(err, "new session")
			defer sess.Close()

			// The id comes from the signed key id alone, the environment cannot claim one.
			ok, err := sess.SendRequest("env", true, ssh.Marshal(
				struct{ Name, Value string }{"NOKKU_SESSION_ID", webSessionID},
			))
			must.NoError(err, "env request")
			is.False(ok, "NOKKU_SESSION_ID is not a client variable")

			_, err = sess.Output("printf env-recorded")
			must.NoError(err, "exec")

			select {
			case <-sink.closed:
			case <-time.After(5 * time.Second):
				t.Fatal("recording sink was never closed")
			}

			mu.Lock()
			defer mu.Unlock()
			if tc.wantPromoted {
				is.Equal(webSessionID, gotID, "recording must carry the key id's session id")
			} else {
				is.NotEmpty(gotID, "recording must carry a session id")
				is.NotEqual(webSessionID, gotID,
					"a direct login must not hijack another session's recording id")
			}
		})
	}
}

// A client must not pile up ptys it never uses.
func TestServerSecondPtyRejected(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()
	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()

	must.NoError(sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{}), "first pty")
	must.Error(sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{}), "second pty was accepted")
}

func TestShellStartsLikeOpenSSH(t *testing.T) {
	account, err := lookupAccount(currentUser(t))
	require.NoError(t, err)
	shell := filepath.Base(account.Shell)

	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()
	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	require.NoError(t, err, "dial")
	defer client.Close()

	for name, tt := range map[string]struct {
		pty, command bool
		want         string
	}{
		"shell":            {want: "argv0=-" + shell},
		"shell on a pty":   {pty: true, want: "argv0=-" + shell},
		"command":          {command: true, want: "argv0=" + shell},
		"command on a pty": {pty: true, command: true, want: "argv0=" + shell},
	} {
		t.Run(name, func(t *testing.T) {
			must := require.New(t)
			sess, sessErr := client.NewSession()
			must.NoError(sessErr, "new session")
			defer sess.Close()
			if tt.pty {
				must.NoError(sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{}), "request pty")
			}
			var out bytes.Buffer
			sess.Stdout = &out
			if tt.command {
				must.NoError(sess.Start("echo argv0=$0"))
			} else {
				sess.Stdin = strings.NewReader("echo argv0=$0\nexit\n")
				must.NoError(sess.Shell())
			}

			done := make(chan error, 1)
			go func() { done <- sess.Wait() }()
			select {
			case waitErr := <-done:
				must.NoError(waitErr, "session")
			case <-time.After(20 * time.Second):
				t.Fatal("the shell did not exit")
			}
			// A pty echoes the typed line and bash puts a bracketed paste escape before the answer.
			lines := strings.Split(strings.ReplaceAll(out.String(), "\r", ""), "\n")
			must.True(
				slices.ContainsFunc(lines, func(l string) bool { return strings.HasSuffix(l, tt.want) }),
				"no line ends with %q: %q", tt.want, lines,
			)
		})
	}
}

func TestSessionConnectionEnv(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()
	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()
	out, err := sess.Output(`printf '%s|%s' "$SSH_CLIENT" "$SSH_CONNECTION"`)
	must.NoError(err)

	local, localPort, _ := net.SplitHostPort(client.LocalAddr().String())
	server, serverPort, _ := net.SplitHostPort(addr)
	must.Equal(
		local+" "+localPort+" "+serverPort+"|"+local+" "+localPort+" "+server+" "+serverPort,
		string(out),
	)
}

func TestMissingHomeRunsInRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone")
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{}, func(s *Server) {
		lookup := s.lookupAccount
		s.lookupAccount = func(name string) (*account, error) {
			account, err := lookup(name)
			if err == nil {
				account.Home = missing
			}
			return account, err
		}
	})
	defer closeFn()
	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	require.NoError(t, err, "dial")
	defer client.Close()
	warning := "Could not chdir to home directory " + missing + ": No such file or directory"

	t.Run("command", func(t *testing.T) {
		sess, sessErr := client.NewSession()
		require.NoError(t, sessErr, "new session")
		defer sess.Close()
		var stdout, stderr bytes.Buffer
		sess.Stdout, sess.Stderr = &stdout, &stderr
		require.NoError(t, sess.Run("pwd"))
		assert.Equal(t, "/\n", stdout.String())
		assert.Contains(t, stderr.String(), warning+"\n")
	})

	t.Run("command on a pty", func(t *testing.T) {
		sess, sessErr := client.NewSession()
		require.NoError(t, sessErr, "new session")
		defer sess.Close()
		require.NoError(t, sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{}), "request pty")
		out, outErr := sess.Output("pwd")
		require.NoError(t, outErr)
		assert.Equal(t, warning+"\r\n/\r\n", string(out), "the warning comes first")
	})

	t.Run("sftp", func(t *testing.T) {
		sc, scErr := sftp.NewClient(client)
		require.NoError(t, scErr, "sftp client")
		defer sc.Close()
		wd, wdErr := sc.Getwd()
		require.NoError(t, wdErr)
		assert.Equal(t, "/", wd, "sftp falls back to / like a shell session")
	})
}

func TestNoTermWithoutPTY(t *testing.T) {
	t.Setenv("TERM", "screen")
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()
	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	require.NoError(t, err, "dial")
	defer client.Close()
	sess, err := client.NewSession()
	require.NoError(t, err, "new session")
	defer sess.Close()

	// What nokkud handed the shell. bash sets TERM=dumb for itself when it has none.
	out, err := sess.Output(`tr '\0' '\n' </proc/$$/environ | grep '^TERM=' || echo unset`)
	require.NoError(t, err)
	assert.Equal(t, "unset\n", string(out))
}

// An interactive session ends at the cap, or a flood would switch recording off for what is typed next.
func TestFullRecordingEndsAnInteractiveSession(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{Policy: Policy{Record: true}}, func(s *Server) {
		require.NoError(t, paths.Verify(), "verify paths")
		s.maxRecording = 1024
	})
	defer closeFn()
	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	require.NoError(t, err, "dial")
	defer client.Close()
	sess, err := client.NewSession()
	require.NoError(t, err, "new session")
	defer sess.Close()
	require.NoError(t, sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{}), "request pty")
	// The pty carries stdout and stderr alike.
	var stdout bytes.Buffer
	sess.Stdout = &stdout

	done := make(chan error, 1)
	go func() { done <- sess.Run("head -c 200000 /dev/urandom | base64; exec sleep 30") }()
	select {
	case err = <-done:
		exitErr, ok := errors.AsType[*ssh.ExitError](err)
		require.True(t, ok, "want an exit status, got %v", err)
		assert.Equal(t, 1, exitErr.ExitStatus())
	case <-time.After(15 * time.Second):
		t.Fatal("the session went on unrecorded")
	}
	assert.Contains(t, stdout.String(), "the recording of this session is full")
}

// An exec session runs on past the cap, a git clone or rsync must not die halfway. The gap is on the audit trail.
func TestFullRecordingKeepsAnExecSessionRunning(t *testing.T) {
	ca := newTestCA(t)
	log, events := auditLog()
	addr, closeFn := startTestServerOpts(t, ca, Options{Policy: Policy{Record: true}, Log: log}, func(s *Server) {
		require.NoError(t, paths.Verify(), "verify paths")
		s.maxRecording = 1024
	})
	defer closeFn()
	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	require.NoError(t, err, "dial")
	defer client.Close()
	sess, err := client.NewSession()
	require.NoError(t, err, "new session")
	defer sess.Close()

	out, err := sess.Output("head -c 200000 /dev/urandom | base64 -w0; echo; echo done")
	require.NoError(t, err, "the session did not finish")
	assert.Len(t, out, 266668+len("\ndone\n"), "output went missing past the cap")
	assert.True(t, bytes.HasSuffix(out, []byte("\ndone\n")))
	assert.Eventually(t, func() bool { return slices.Contains(events(), eventRecordingDegraded) },
		5*time.Second, 20*time.Millisecond, "the unrecorded rest left no audit event")
}
