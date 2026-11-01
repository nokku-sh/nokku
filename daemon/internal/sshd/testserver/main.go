// Command testserver runs the server for the interop tests. It is not shipped.
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

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
	"github.com/nokku-sh/nokku/daemon/internal/sshd"
	"github.com/nokku-sh/nokku/daemon/internal/state"
	"github.com/nokku-sh/nokku/daemon/internal/sysutil"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	configDir := flag.String(
		"config-dir", "",
		"state directory holding daemon.json and the host key",
	)
	allowNonRoot := flag.Bool("allow-nonroot", false, "run as non-root, sessions restricted to this account")
	flag.Parse()

	// The server re-execs this entrypoint as the target user for its helpers.
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

	st, err := state.Load()
	if err != nil {
		fail(err.Error())
	}
	access := *st.Access()
	access.DaemonConfig = &nokkuv1.DaemonConfig{RecordSessions: new(false)}
	if *allowNonRoot {
		// Nothing drops privileges here, so only this account may log in.
		self, userErr := user.Current()
		if userErr != nil {
			fail(userErr.Error())
		}
		access.Principals = map[string][]string{self.Username: access.Principals[self.Username]}
	}

	srv, err := sshd.New(nil)
	if err != nil {
		fail(err.Error())
	}
	srv.SetAccess(&access)

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
