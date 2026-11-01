package email

import (
	"encoding/base64"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRelay offers CRAM-MD5, go-mail keeps PLAIN and LOGIN off plain TCP.
func fakeRelay(t *testing.T, authReply string) (port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSMTP(conn, authReply)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func serveSMTP(conn net.Conn, authReply string) {
	defer func() { _ = conn.Close() }()
	tp := textproto.NewConn(conn)
	_ = tp.PrintfLine("220 fake ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		cmd, _, _ := strings.Cut(line, " ")
		switch strings.ToUpper(cmd) {
		case "EHLO":
			_ = tp.PrintfLine("250-fake")
			_ = tp.PrintfLine("250 AUTH CRAM-MD5")
		case "AUTH":
			_ = tp.PrintfLine("334 %s", base64.StdEncoding.EncodeToString([]byte("<1@fake>")))
			if _, err := tp.ReadLine(); err != nil {
				return
			}
			_ = tp.PrintfLine("%s", authReply)
		case "QUIT":
			_ = tp.PrintfLine("221 bye")
			return
		default:
			_ = tp.PrintfLine("250 ok")
		}
	}
}

func setRelayEnv(t *testing.T, port int) {
	t.Helper()
	t.Setenv("NOKKU_SMTP_HOST", "127.0.0.1")
	t.Setenv("NOKKU_SMTP_PORT", strconv.Itoa(port))
	t.Setenv("NOKKU_SMTP_USERNAME", "mailer")
	t.Setenv("NOKKU_SMTP_PASSWORD", "wrong-or-right")
	t.Setenv("NOKKU_EMAIL_SENDER", "noreply@nokku.test")
}

func TestNew_RejectedLoginFailsTheStart(t *testing.T) {
	setRelayEnv(t, fakeRelay(t, "535 5.7.8 Authentication Failed"))

	_, err := New(t.Context(), "http://localhost")
	require.Error(t, err, "a relay that rejects the credentials let the server start")
	assert.Contains(t, err.Error(), "NOKKU_SMTP_PASSWORD", "the error does not name the setting")
	assert.NotContains(t, err.Error(), "wrong-or-right", "the password is in the error")
}

func TestNew_AcceptedLoginStarts(t *testing.T) {
	setRelayEnv(t, fakeRelay(t, "235 2.7.0 ok"))

	svc, err := New(t.Context(), "http://localhost")
	require.NoError(t, err)
	assert.True(t, svc.HasSMTP())
}

// An outage of the relay must not keep the control plane from starting.
func TestNew_UnreachableRelayStillStarts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	setRelayEnv(t, port)

	svc, err := New(t.Context(), "http://localhost")
	require.NoError(t, err, "a relay that does not answer stopped the start")
	assert.True(t, svc.HasSMTP())
}

// A relay that connects and then says nothing must not hold up the start.
func TestNew_HungRelayDoesNotHoldUpTheStart(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	setRelayEnv(t, ln.Addr().(*net.TCPAddr).Port)
	relayCheckTimeout = 100 * time.Millisecond
	t.Cleanup(func() { relayCheckTimeout = 3 * time.Second })

	start := time.Now()
	svc, err := New(t.Context(), "http://localhost")
	require.NoError(t, err, "a relay that hangs stopped the start")
	assert.True(t, svc.HasSMTP())
	assert.Less(t, time.Since(start), 2*time.Second, "the check waited out the relay")
}
