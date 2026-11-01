package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/nokku-sh/nokku/cli/internal/state"
)

// Direct dials run alone this long, a reachable endpoint answers within it.
const relayHeadStart = 300 * time.Millisecond

type RelayDialer func(ctx context.Context, target *state.Target) (io.ReadWriteCloser, error)

type dialResult struct {
	conn io.ReadWriteCloser
	err  error
}

// Proxy races endpoints and relay. Private addresses must show the host key.
func Proxy(ctx context.Context, target *state.Target, port string, relay RelayDialer, forceRelay bool) error {
	if forceRelay && target.Manual() {
		return fmt.Errorf("%s has no daemon, so it cannot be reached through the relay", target.Name)
	}
	if target.Manual() && len(target.Endpoints) == 0 {
		return fmt.Errorf("%s has no address, run nk sync on it again", target.Name)
	}

	// Cancelled on a win. The relay uses ctx, its stream is the connection.
	dialCtx, stopDials := context.WithCancel(ctx)
	defer stopDials()
	results := make(chan dialResult)
	pending := 0
	if !forceRelay {
		for _, ep := range target.Endpoints {
			pending++
			go func() { results <- dialDirect(dialCtx, target, endpointAddr(ep, port)) }()
		}
	}
	var relayStart <-chan time.Time
	if !target.Manual() {
		relayStart = time.After(relayHeadStart)
		if pending == 0 {
			relayStart = time.After(0)
		}
	}

	var errs []error
	for pending > 0 || relayStart != nil {
		select {
		case <-relayStart:
			relayStart = nil
			pending++
			go func() {
				conn, err := relay(ctx, target)
				results <- dialResult{conn, err}
			}()
		case r := <-results:
			pending--
			if r.err == nil {
				stopDials()
				go closeLosers(results, pending)
				return pipe(ctx, r.conn)
			}
			errs = append(errs, r.err)
			if pending == 0 && relayStart != nil {
				relayStart = time.After(0)
			}
		}
	}
	return fmt.Errorf("cannot reach %s: %w", target.Name, errors.Join(errs...))
}

func dialDirect(ctx context.Context, target *state.Target, addr string) dialResult {
	if needsVerify(target, addr) {
		if err := verifyHost(ctx, addr, target); err != nil {
			return dialResult{err: err}
		}
	}
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	return dialResult{conn, err}
}

func closeLosers(results <-chan dialResult, n int) {
	for range n {
		if r := <-results; r.conn != nil {
			_ = r.conn.Close()
		}
	}
}

func endpointAddr(endpoint, port string) string {
	if _, _, err := net.SplitHostPort(endpoint); err == nil {
		return endpoint
	}
	return net.JoinHostPort(endpoint, port)
}

// Ends when the server closes. Waiting on stdin too would hold ssh up.
func pipe(ctx context.Context, conn io.ReadWriteCloser) error {
	defer func() { _ = conn.Close() }()
	// Closing is the only way to unblock the copies on cancel.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	stdin := os.Stdin
	go func() {
		_, _ = io.Copy(conn, stdin)
		// Half-close so sshd sees EOF but can keep sending.
		if hc, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = hc.CloseWrite()
		}
	}()
	_, err := io.Copy(os.Stdout, conn)
	return err
}
