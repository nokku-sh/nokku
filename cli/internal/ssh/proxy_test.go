package ssh

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/cli/internal/state"
)

const blackhole = "127.0.0.1:1"

// relayStubConn answers a half-close with EOF, like sshd does once it has seen the client's EOF.
type relayStubConn struct{ halfClosed chan struct{} }

func (c *relayStubConn) Read([]byte) (int, error) {
	<-c.halfClosed
	return 0, io.EOF
}
func (c *relayStubConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *relayStubConn) CloseWrite() error           { close(c.halfClosed); return nil }
func (c *relayStubConn) Close() error                { return nil }

type relayStub struct {
	calls int
	err   error
}

func (s *relayStub) dial(context.Context, *state.Target) (io.ReadWriteCloser, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return &relayStubConn{halfClosed: make(chan struct{})}, nil
}

// swapStdin replaces [os.Stdin] with a pipe and returns its write end.
func swapStdin(t *testing.T) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	old := os.Stdin
	os.Stdin = r //nolint:reassign // test isolation
	t.Cleanup(func() {
		os.Stdin = old //nolint:reassign // test isolation
		_ = w.Close()
		_ = r.Close()
	})
	return w
}

// stdinEOF closes stdin at once, so the stdin copy ends.
func stdinEOF(t *testing.T) {
	t.Helper()
	require.NoError(t, swapStdin(t).Close())
}

func TestProxyDaemonFallsBackToRelay(t *testing.T) {
	stdinEOF(t)
	stub := &relayStub{}
	target := &state.Target{Name: "prod", DaemonID: "d", Endpoints: []string{blackhole}}

	require.NoError(t, Proxy(t.Context(), target, "22", stub.dial, false), "stdin EOF half-closes the relay")
	assert.Equal(t, 1, stub.calls)
}

// A daemon that only reports private addresses: the relay wins long before the direct dial times out.
func TestProxyRelayDoesNotWaitForSlowEndpoint(t *testing.T) {
	stdinEOF(t)
	stub := &relayStub{}
	// TEST-NET-1 is never routed, so the dial hangs until its timeout.
	target := &state.Target{Name: "prod", DaemonID: "d", Endpoints: []string{"192.0.2.1:22"}}

	start := time.Now()
	require.NoError(t, Proxy(t.Context(), target, "22", stub.dial, false))
	assert.Less(t, time.Since(start), time.Second, "relay waited for the direct dial")
	assert.Equal(t, 1, stub.calls)
}

func TestProxyReportsDialAndRelayErrors(t *testing.T) {
	t.Parallel()
	stub := &relayStub{err: errors.New("relay down")}
	target := &state.Target{Name: "prod", DaemonID: "d", Endpoints: []string{blackhole}}

	err := Proxy(t.Context(), target, "22", stub.dial, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), blackhole)
	assert.Contains(t, err.Error(), "relay down")
}

func TestProxyManualTargetNeverUsesRelay(t *testing.T) {
	t.Parallel()
	stub := &relayStub{}
	target := &state.Target{Name: "prod", Endpoints: []string{blackhole, "127.0.0.2:1"}}

	err := Proxy(t.Context(), target, "22", stub.dial, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), blackhole)
	assert.Contains(t, err.Error(), "127.0.0.2:1", "every dial error must reach the user")
	assert.Zero(t, stub.calls)

	err = Proxy(t.Context(), target, "22", stub.dial, true)
	require.ErrorContains(t, err, "no daemon")
	assert.Zero(t, stub.calls)
}

func TestProxyDirectAndForcedRelay(t *testing.T) {
	stdinEOF(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	accepted := make(chan struct{}, 2)
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			accepted <- struct{}{}
			_ = conn.Close()
		}
	}()

	stub := &relayStub{}
	target := &state.Target{Name: "prod", DaemonID: "d", Endpoints: []string{ln.Addr().String()}}

	require.NoError(t, Proxy(t.Context(), target, "22", stub.dial, false))
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("direct connection was not established")
	}
	assert.Zero(t, stub.calls)

	require.NoError(t, Proxy(t.Context(), target, "22", stub.dial, true))
	assert.Equal(t, 1, stub.calls)
	assert.Empty(t, accepted, "forced relay must not dial endpoints")
}

// brokenConn fails on read, like a relay stream that died.
type brokenConn struct{}

func (brokenConn) Read([]byte) (int, error)    { return 0, io.ErrUnexpectedEOF }
func (brokenConn) Write(p []byte) (int, error) { return len(p), nil }
func (brokenConn) Close() error                { return nil }

func TestPipeReportsConnectionError(t *testing.T) {
	stdinEOF(t)
	require.ErrorIs(t, pipe(t.Context(), brokenConn{}), io.ErrUnexpectedEOF)
}

func TestPipeEndsWhenTheServerCloses(t *testing.T) {
	swapStdin(t)
	client, server := net.Pipe()
	require.NoError(t, server.Close())

	done := make(chan error, 1)
	go func() { done <- pipe(t.Context(), client) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pipe waited for stdin after the server closed")
	}
}

func TestEndpointAddr(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "10.0.0.1:22", endpointAddr("10.0.0.1", "22"))
	assert.Equal(t, "10.0.0.1:2222", endpointAddr("10.0.0.1:2222", "22"))
	assert.Equal(t, "[::1]:22", endpointAddr("::1", "22"))
	assert.Equal(t, "host.example:22", endpointAddr("host.example", "22"))
}
