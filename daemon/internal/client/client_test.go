package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/user"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
	"github.com/nokku-sh/nokku/daemon/internal/report"
	"github.com/nokku-sh/nokku/daemon/internal/sshd"
	"github.com/nokku-sh/nokku/daemon/internal/state"
)

// deadPort is reserved and nothing listens on it, so a dial is refused at once.
const deadPort = "http://127.0.0.1:1"

// unreachableCore counts calls, the sync point a refused dial does not give.
type unreachableCore struct {
	http.RoundTripper

	syncs   atomic.Int32
	streams atomic.Int32
}

func (u *unreachableCore) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.URL.Path {
	case nokkuv1connect.DaemonControlServiceSyncDaemonProcedure:
		u.syncs.Add(1)
	case nokkuv1connect.DaemonControlServiceConnectProcedure:
		u.streams.Add(1)
	}
	return u.RoundTripper.RoundTrip(req)
}

// A core down at start leaves the daemon on its last sync, usable and closed.
// The file is hand-written, a release must read what the one before it left.
func TestRunServesFromCacheWhenCoreIsDown(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	must.NoError(paths.Verify())
	cur, err := user.Current()
	must.NoError(err)
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	must.NoError(err)
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	must.NoError(err)

	must.NoError(os.WriteFile(paths.StateFile(), fmt.Appendf(nil, `{
		"target_id": "target-1",
		"daemon_id": "daemon-1",
		"session_token": "session",
		"access": {
			"principals": {%q: ["subject-1"]},
			"ca": %q,
			"state_hash": "aGVsZA==",
			"synced_at": %q
		}
	}`, cur.Username, ssh.MarshalAuthorizedKey(caSigner.PublicKey()),
		// Within the week a saved state is good for, see TestStaleAccessTakesNoNewLogins for past it.
		time.Now().Add(-time.Hour).Format(time.RFC3339)), 0o600))

	st, err := state.Load()
	must.NoError(err)
	srv, err := sshd.New(nil, nil)
	must.NoError(err)
	// As run does in cmd/nokkud, which needs root and has no test itself.
	srv.SetAccess(st.Access())
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must.NoError(err)

	core := &unreachableCore{RoundTripper: http.DefaultTransport}
	c := &Client{
		state: st,
		ctl: nokkuv1connect.NewDaemonControlServiceClient(
			connect.NewClient(connecthttp.NewTransport(&http.Client{Transport: core}, deadPort)),
		),
		renew:   make(chan struct{}, 1),
		reports: report.Open(paths.ReportsFile()),
	}
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	wg.Go(func() { srv.Serve(ctx, l) })
	ran := make(chan error, 1)
	wg.Go(func() { ran <- c.Run(ctx, srv, netip.MustParseAddrPort(l.Addr().String())) })

	// Run opens the stream only after it dealt with the failed sync.
	must.Eventually(func() bool { return core.streams.Load() > 0 }, 5*time.Second, 5*time.Millisecond,
		"Run never got past the first sync")
	must.Positive(core.syncs.Load(), "the first sync never tried the core")

	client, err := certLogin(t, l.Addr().String(), cur.Username, caSigner, "subject-1")
	must.NoError(err, "the cached principal does not log in with the core down")
	sess, err := client.NewSession()
	must.NoError(err)
	out, err := sess.Output("echo cached")
	must.NoError(err, "the login got no working session")
	is.Equal("cached\n", string(out))
	must.NoError(client.Close())

	// The same CA, so the principal is the only thing that can refuse it.
	_, err = certLogin(t, l.Addr().String(), cur.Username, caSigner, "subject-2")
	must.ErrorContains(err, "unable to authenticate", "a principal the cache does not name got in")

	select {
	case stopped := <-ran:
		t.Fatalf("Run gave up with the core down: %v", stopped)
	default:
	}
	cancel()
	wg.Wait()
	must.NoError(<-ran, "a core that is down must not end the daemon")

	restarted, err := state.Load()
	must.NoError(err)
	is.Equal([]string{"subject-1"}, restarted.Access().Principals[cur.Username], "the failed sync touched the cache")
}

// certLogin dials with a fresh key, certified by ca for one principal.
func certLogin(t *testing.T, addr, username string, ca ssh.Signer, principal string) (*ssh.Client, error) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	cert := &ssh.Certificate{
		Key:             signer.PublicKey(),
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{principal},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	require.NoError(t, cert.SignCert(rand.Reader, ca))
	certSigner, err := ssh.NewCertSigner(cert, signer)
	require.NoError(t, err)
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106
		Timeout:         10 * time.Second,
	})
}
