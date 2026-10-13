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

// relayStubConn EOFs on read, so pipe completes without a real peer.
type relayStubConn struct{ stub *relayStub }

func (c *relayStubConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *relayStubConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *relayStubConn) CloseWrite() error           { c.stub.halfClosed = true; return nil }
func (c *relayStubConn) Close() error                { return nil }

type relayStub struct {
	calls      int
	halfClosed bool
	err        error
}

func (s *relayStub) dial(context.Context, *state.Target) (io.ReadWriteCloser, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return &relayStubConn{stub: s}, nil
}

// stdinEOF swaps [os.Stdin] for a closed pipe so the stdin copy ends at once.
func stdinEOF(t *testing.T) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	require.NoError(t, w.Close())
	old := os.Stdin
	os.Stdin = r //nolint:reassign // test isolation
	t.Cleanup(func() {
		os.Stdin = old //nolint:reassign // test isolation
		_ = r.Close()
	})
}

func TestProxyDaemonFallsBackToRelay(t *testing.T) {
	stdinEOF(t)
	stub := &relayStub{}
	target := &state.Target{Name: "prod", DaemonID: "d", Endpoints: []string{blackhole}}

	require.NoError(t, Proxy(t.Context(), target, "22", stub.dial, false))
	assert.Equal(t, 1, stub.calls)
	assert.True(t, stub.halfClosed, "stdin EOF must half-close the relay stream")
}

// TestProxyRelayDoesNotWaitForSlowEndpoint covers the remote user whose
// daemon only reports private addresses: the relay must win long before the
// direct dial times out.
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

func TestEndpointAddr(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "10.0.0.1:22", endpointAddr("10.0.0.1", "22"))
	assert.Equal(t, "10.0.0.1:2222", endpointAddr("10.0.0.1:2222", "22"))
	assert.Equal(t, "[::1]:22", endpointAddr("::1", "22"))
	assert.Equal(t, "host.example:22", endpointAddr("host.example", "22"))
}
