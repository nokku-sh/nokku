package sshd

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

type auditLine struct {
	Msg   string    `json:"msg"`
	Type  eventType `json:"type"`
	Error string    `json:"error"`
}

// auditLines is auditLog with the error of each event kept.
func auditLines() (*slog.Logger, func() []auditLine) {
	var mu sync.Mutex
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(lockedWriter{mu: &mu, w: &buf}, nil))
	return log, func() []auditLine {
		mu.Lock()
		defer mu.Unlock()
		var lines []auditLine
		for raw := range bytes.Lines(buf.Bytes()) {
			var line auditLine
			if json.Unmarshal(raw, &line) == nil && line.Msg == "audit" {
				lines = append(lines, line)
			}
		}
		return lines
	}
}

func degradedReasons(lines []auditLine) []string {
	var reasons []string
	for _, line := range lines {
		if line.Type == eventRecordingDegraded {
			reasons = append(reasons, line.Error)
		}
	}
	return reasons
}

func countEvents(lines []auditLine, typ eventType) int {
	n := 0
	for _, line := range lines {
		if line.Type == typ {
			n++
		}
	}
	return n
}

// Recording fails open, so a host whose recorder cannot start still lets its admins in. The gap is on the audit trail.
func TestRecordingThatCannotStartLeavesTheSessionRunning(t *testing.T) {
	ca := newTestCA(t)
	log, audit := auditLines()
	addr, closeFn := startTestServerOpts(t, ca, withLog(log), withPolicy(Policy{Record: true}), func(*Server) {
		// A file where the recordings directory belongs, so New cannot create one. Unlike a chmod this holds for root.
		require.NoError(t, os.WriteFile(paths.RecordsDir(), nil, 0o600))
	})
	defer closeFn()
	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	require.NoError(t, err, "dial")
	defer client.Close()

	for name, pty := range map[string]bool{"exec": false, "pty": true} {
		t.Run(name, func(t *testing.T) {
			sess, sessErr := client.NewSession()
			require.NoError(t, sessErr, "new session")
			defer sess.Close()
			if pty {
				require.NoError(t, sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{}), "request pty")
			}
			out, runErr := sess.Output("echo still-here")
			require.NoError(t, runErr, "the session must run unrecorded")
			assert.Contains(t, string(out), "still-here")
		})
	}

	require.Eventually(t, func() bool { return len(degradedReasons(audit())) == 2 },
		5*time.Second, 20*time.Millisecond, "one recording_degraded per session, got %v", audit())
	for _, reason := range degradedReasons(audit()) {
		// The errno depends on the host, a small tmpfs trips the free space check first.
		assert.True(t, strings.HasPrefix(reason, "not recorded: "), "reason %q", reason)
	}
}

// A disk that fills mid-session fails the recorder's writes. The session runs on, the file stops where the disk did
// and keeps its .part name, and the gap is on the audit trail.
func TestWriteErrorMidSessionIsOnTheAuditTrail(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	log, audit := auditLines()
	addr, closeFn := startTestServerOpts(t, ca, withLog(log), withPolicy(Policy{Record: true}), func(*Server) {
		require.NoError(t, paths.Verify(), "verify paths")
	})
	defer closeFn()
	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()
	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()

	const fileLimit = 64 << 10
	var limit syscall.Rlimit
	must.NoError(syscall.Getrlimit(syscall.RLIMIT_FSIZE, &limit))
	lowered := limit
	lowered.Cur = fileLimit
	// A write past RLIMIT_FSIZE fails with EFBIG like on a full disk. Go ignores the SIGXFSZ that comes with it.
	must.NoError(syscall.Setrlimit(syscall.RLIMIT_FSIZE, &lowered))
	restore := sync.OnceFunc(func() { _ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit) })
	t.Cleanup(restore)

	out, err := sess.Output("head -c 200000 /dev/urandom | base64 -w0; echo; echo done")
	restore()
	must.NoError(err, "the session did not finish")
	is.Len(out, 266668+len("\ndone\n"), "output went missing after the failed write")
	is.True(bytes.HasSuffix(out, []byte("\ndone\n")))

	files, err := filepath.Glob(filepath.Join(paths.RecordsDir(), "*"))
	must.NoError(err)
	must.Len(files, 1, "the cut recording stays pending")
	is.True(strings.HasSuffix(files[0], ".part"), "a cut recording took the name of a whole one: %s", files[0])
	info, err := os.Stat(files[0])
	must.NoError(err)
	is.LessOrEqual(info.Size(), int64(fileLimit))
	f, err := os.Open(files[0])
	must.NoError(err)
	defer f.Close()
	zr, err := gzip.NewReader(f)
	must.NoError(err)
	text, err := io.ReadAll(zr)
	must.ErrorIs(err, io.ErrUnexpectedEOF, "the cut file has no gzip footer")
	is.NotContains(string(text), "done")

	must.Eventually(func() bool { return countEvents(audit(), eventSessionEnd) == 1 },
		5*time.Second, 20*time.Millisecond, "the session never ended on the audit trail")
	reasons := degradedReasons(audit())
	must.Len(reasons, 1, "one recording_degraded for the write that failed")
	is.True(strings.HasPrefix(reasons[0], "recording stopped: write failed: "), "reason %q", reasons[0])
}

// The cap ends an interactive session, the one exception to failing open, and says so on the audit trail.
func TestFullRecordingEndsAnInteractiveSessionOnTheAuditTrail(t *testing.T) {
	ca := newTestCA(t)
	log, audit := auditLines()
	addr, closeFn := startTestServerOpts(t, ca, withLog(log), withPolicy(Policy{Record: true}), func(s *Server) {
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
	require.Eventually(t, func() bool { return len(degradedReasons(audit())) == 1 },
		5*time.Second, 20*time.Millisecond, "the cap left no audit event")
	assert.Equal(t, []string{"size limit reached, session ended"}, degradedReasons(audit()))
	assert.True(t, slices.ContainsFunc(audit(), func(l auditLine) bool { return l.Type == eventSessionEnd }))
}
