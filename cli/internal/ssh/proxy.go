// Package ssh manages the SSH identity, certificates, and proxy plumbing for nk.
package ssh

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/nokku-sh/nokku/cli/internal/state"
)

// RelayDialer opens a relayed connection to a daemon target through the
// backend.
type RelayDialer func(ctx context.Context, target *state.Target) (io.ReadWriteCloser, error)

// relayHeadStart is how long direct dials run alone before the relay joins
// the race. A reachable endpoint answers well within it.
const relayHeadStart = 300 * time.Millisecond

type dialResult struct {
	conn io.ReadWriteCloser
	err  error
}

// Proxy pipes an ssh ProxyCommand connection to the target. All endpoints are
// dialed at once and a daemon target races the relay against them, so an
// unreachable private address never delays the connection. forceRelay skips
// the direct dials.
func Proxy(ctx context.Context, target *state.Target, port string, relay RelayDialer, forceRelay bool) error {
	if forceRelay && target.Manual() {
		return fmt.Errorf("%s has no daemon, so it cannot be reached through the relay", target.Name)
	}
	if target.Manual() && len(target.Endpoints) == 0 {
		return fmt.Errorf("%s has no address, run nk sync on it again", target.Name)
	}

	// Direct dials stop once a winner is picked. The relay gets ctx itself,
	// its stream lives as long as ctx does.
	dialCtx, stopDials := context.WithCancel(ctx)
	defer stopDials()
	results := make(chan dialResult)
	pending := 0
	if !forceRelay {
		dialer := net.Dialer{Timeout: 2 * time.Second}
		for _, ep := range target.Endpoints {
			pending++
			go func() {
				conn, err := dialer.DialContext(dialCtx, "tcp", endpointAddr(ep, port))
				results <- dialResult{conn, err}
			}()
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
			if r.err != nil {
				errs = append(errs, r.err)
				if pending == 0 && relayStart != nil {
					relayStart = time.After(0)
				}
				continue
			}
			stopDials()
			go closeLosers(results, pending)
			return pipe(ctx, r.conn)
		}
	}
	return fmt.Errorf("cannot reach %s: %w", target.Name, errors.Join(errs...))
}

// closeLosers closes connections that won their dial after another one did.
func closeLosers(results <-chan dialResult, n int) {
	for range n {
		if r := <-results; r.conn != nil {
			_ = r.conn.Close()
		}
	}
}

// endpointAddr keeps an endpoint's own port and uses port otherwise.
func endpointAddr(endpoint, port string) string {
	if _, _, err := net.SplitHostPort(endpoint); err == nil {
		return endpoint
	}
	return net.JoinHostPort(endpoint, port)
}

func pipe(ctx context.Context, conn io.ReadWriteCloser) error {
	defer func() { _ = conn.Close() }()
	// Closing is the only way to unblock the copies on cancel.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	var wg sync.WaitGroup
	var outErr, inErr error
	wg.Go(func() { _, outErr = io.Copy(os.Stdout, conn) })
	wg.Go(func() {
		_, inErr = io.Copy(conn, os.Stdin)
		// Half-close so sshd sees EOF but can keep sending.
		if hc, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = hc.CloseWrite()
		}
	})
	wg.Wait()
	return cmp.Or(outErr, inErr)
}
