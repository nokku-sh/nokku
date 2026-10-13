// Command testserver is built by internal/sshd/interop_test.go for the interop tests. It is not shipped.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"os/user"
	"syscall"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
	"github.com/nokku-sh/nokku/daemon/internal/sshd"
	"github.com/nokku-sh/nokku/daemon/internal/state"
	"github.com/nokku-sh/nokku/daemon/internal/sysutil"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	configDir := flag.String(
		"config-dir", "",
		"state directory holding cache.json and the host key",
	)
	allowNonRoot := flag.Bool("allow-nonroot", false, "run as non-root, sessions restricted to this account")
	flag.Parse()

	// The embedded server re-execs this entrypoint as the target user for its helpers.
	if flag.NArg() > 0 {
		if err := sshd.RunHelper(context.Background(), flag.Arg(0), flag.Args()[1:]); err != nil {
			fail(err.Error())
		}
		return
	}

	if *configDir == "" {
		fail("config-dir is required")
	}
	if !*allowNonRoot {
		if err := sysutil.IsRoot(); err != nil {
			fail(err.Error())
		}
	}
	if err := os.Setenv("NOKKUD_DATA_DIR", *configDir); err != nil {
		fail(err.Error())
	}
	if err := paths.Verify(); err != nil {
		fail(err.Error())
	}

	cache := state.NewCache()
	if err := cache.Load(); err != nil {
		fail(err.Error())
	}

	policy := sshd.DefaultPolicy
	policy.Record = false
	opts := sshd.Options{Principals: cache.CertPrincipals, Policy: policy}
	if *allowNonRoot {
		// Without privilege dropping every session runs as this account, so only this account may log in.
		self, userErr := user.Current()
		if userErr != nil {
			fail(userErr.Error())
		}
		opts.Principals = func(username string) []string {
			if username != self.Username {
				return nil
			}
			return cache.CertPrincipals(username)
		}
	}

	srv, err := sshd.New(opts)
	if err != nil {
		fail(err.Error())
	}
	srv.SetTrust(cache.CAs())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", *addr)
	if err != nil {
		fail(err.Error())
	}
	fmt.Println(l.Addr().String())
	srv.Serve(ctx, l)
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
