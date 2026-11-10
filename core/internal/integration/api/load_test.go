//go:build integration

package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
	nklogin "github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/core/internal/api"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/realip"
)

// fakeDaemon speaks nokkud's part of the control stream: a heartbeat with what it holds, and a sync when the core
// says so. Keep it in step with daemon/internal/client.
type fakeDaemon struct {
	fleet  *fakeFleet
	key    *ecdsa.PrivateKey
	id     string
	target string
	token  string
	source string
	// More letters than digits, or the core takes it for a default and makes a name up.
	host string

	stream  nokkuv1connect.DaemonControlServiceConnectClientStream
	sending sync.Mutex

	mu         sync.Mutex
	hash       []byte
	principals []string
}

type fakeFleet struct {
	cfg     *config.Config
	srv     *httptest.Server
	syncs   atomic.Int64
	failed  atomic.Int64
	lastErr atomic.Pointer[error]
}

func (f *fakeFleet) fail(err error) {
	f.failed.Add(1)
	f.lastErr.Store(&err)
}

// call signs one RPC the way nokkud does, from an address of its own so the per-address limits see a fleet.
func (d *fakeDaemon) call(ctx context.Context, procedure string) (context.Context, error) {
	proof, err := signDPoP(d.key, procedure, d.token, d.fleet.cfg.IAM.DPoP.CurrentNonce())
	if err != nil {
		return nil, err
	}
	ctx, info := connect.NewClientContext(ctx)
	if d.token != "" {
		info.RequestHeader().Set("Authorization", "DPoP "+d.token)
	}
	info.RequestHeader().Set("DPoP", proof)
	info.RequestHeader().Set("X-Forwarded-For", d.source)
	return ctx, nil
}

func (d *fakeDaemon) enroll(ctx context.Context, secret string) error {
	ctx, err := d.call(ctx, nokkuv1connect.DaemonControlServiceEnrollDaemonProcedure)
	if err != nil {
		return err
	}
	res, err := nokkuv1connect.NewDaemonControlServiceClient(clientOn(d.fleet.srv)).
		EnrollDaemon(ctx, &nokkuv1.EnrollDaemonRequest{
			Token: &secret, Metadata: map[string]string{"hostname": d.host},
		})
	if err != nil {
		return err
	}
	d.id, d.target, d.token = res.GetId(), res.GetTargetId(), res.GetAccessToken()
	return nil
}

func (d *fakeDaemon) sync(ctx context.Context) error {
	ctx, err := d.call(ctx, nokkuv1connect.DaemonControlServiceSyncDaemonProcedure)
	if err != nil {
		return err
	}
	d.fleet.syncs.Add(1)
	res, err := nokkuv1connect.NewDaemonControlServiceClient(clientOn(d.fleet.srv)).
		SyncDaemon(ctx, &nokkuv1.SyncDaemonRequest{Users: []string{"root"}})
	if err != nil {
		return err
	}
	var principals []string
	for _, account := range res.GetPrincipals() {
		principals = append(principals, account.GetCertPrincipals()...)
	}
	d.mu.Lock()
	d.hash, d.principals = res.GetStateHash(), principals
	d.mu.Unlock()
	return nil
}

func (d *fakeDaemon) heartbeat() error {
	d.sending.Lock()
	defer d.sending.Unlock()
	return d.stream.Send(&nokkuv1.ConnectRequest{
		Msg: &nokkuv1.ConnectRequest_Heartbeat{Heartbeat: &nokkuv1.Heartbeat{StateHash: d.holds()}},
	})
}

// connect holds the stream until ctx ends and syncs on every update, like runControlStream.
func (d *fakeDaemon) connect(ctx context.Context) error {
	ctx, err := d.call(ctx, nokkuv1connect.DaemonControlServiceConnectProcedure)
	if err != nil {
		return err
	}
	if d.stream, err = nokkuv1connect.NewDaemonControlServiceClient(clientOn(d.fleet.srv)).Connect(ctx); err != nil {
		return err
	}
	go func() {
		for {
			msg, recvErr := d.stream.Receive()
			if recvErr != nil {
				if ctx.Err() == nil {
					d.fleet.fail(recvErr)
				}
				return
			}
			update := msg.GetStateUpdate()
			if update == nil || len(update.GetStateHash()) > 0 && bytes.Equal(update.GetStateHash(), d.holds()) {
				continue
			}
			if syncErr := d.sync(ctx); syncErr != nil && ctx.Err() == nil {
				d.fleet.fail(syncErr)
			}
		}
	}()
	return d.heartbeat()
}

func (d *fakeDaemon) holds() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.hash
}

func (d *fakeDaemon) lets(principal string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Contains(d.principals, principal)
}

// settle waits until no daemon has synced for a moment, and says when the last one did.
func (f *fakeFleet) settle(t *testing.T) time.Time {
	t.Helper()
	last, at := f.syncs.Load(), time.Now()
	require.Eventually(t, func() bool {
		if now := f.syncs.Load(); now != last {
			last, at = now, time.Now()
		}
		return time.Since(at) > 2*time.Second
	}, 5*time.Minute, 50*time.Millisecond, "the fleet never went quiet")
	return at
}

// TestLoadFanOut is a measuring tool, not a check: what one access change and one round of heartbeats cost with a
// fleet connected. Run it with task core:load -- 10000.
func TestLoadFanOut(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("NOKKU_LOAD_DAEMONS"))
	if n <= 0 {
		t.Skip("set NOKKU_LOAD_DAEMONS to the number of fake daemons")
	}
	cfg, _ := enterprise(t)
	// The licensed config on a server of its own, a control stream needs HTTP/2.
	srv := httptest.NewUnstartedServer(serving(api.New(cfg).Handler(t.Context())))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	// One address per daemon. The suite's server sees them all on loopback.
	require.NoError(t, realip.SetTrustedProxies([]string{"127.0.0.1/32", "::1/128"}))
	t.Cleanup(func() { _ = realip.SetTrustedProxies(nil) })
	ctx, stop := context.WithCancel(t.Context())
	t.Cleanup(stop)

	adminAuth := header("Authorization",
		"Bearer "+seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN))
	admin := clientOn(srv, adminAuth)
	created, err := nokkuv1connect.NewJoinTokenServiceClient(admin).
		CreateJoinToken(ctx, &nokkuv1.CreateJoinTokenRequest{AutoApprove: new(true)})
	require.NoError(t, err)

	fleet := &fakeFleet{cfg: cfg, srv: srv}
	daemons := make([]*fakeDaemon, n)
	each := func(what string, do func(d *fakeDaemon) error) time.Duration {
		t.Helper()
		start := time.Now()
		var wg sync.WaitGroup
		slots := make(chan struct{}, 64)
		for _, d := range daemons {
			slots <- struct{}{}
			wg.Go(func() {
				defer func() { <-slots }()
				if doErr := do(d); doErr != nil {
					fleet.fail(doErr)
				}
			})
		}
		wg.Wait()
		if failed := fleet.failed.Load(); failed > 0 {
			require.FailNow(t, what+" failed", "%d times, last: %v", failed, *fleet.lastErr.Load())
		}
		return time.Since(start)
	}
	for i := range daemons {
		key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, keyErr)
		daemons[i] = &fakeDaemon{
			fleet: fleet, key: key, source: fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255),
			host: fmt.Sprintf("loadserver%06d", i),
		}
	}
	enrolled := each("enroll", func(d *fakeDaemon) error { return d.enroll(ctx, created.GetSecret()) })
	connected := each("connect", func(d *fakeDaemon) error { return d.connect(ctx) })
	fleet.settle(t)

	owner, err := pgx.Connect(ctx, "")
	require.NoError(t, err)
	defer owner.Close(context.WithoutCancel(ctx))
	commits := func() int64 {
		t.Helper()
		// An idle backend reports its counters up to ten seconds late.
		time.Sleep(11 * time.Second)
		var count int64
		require.NoError(t, owner.QueryRow(ctx,
			"SELECT xact_commit FROM pg_stat_database WHERE datname = current_database()").Scan(&count))
		return count
	}

	// One person on one account of the first server, then taken away again.
	first := daemons[0]
	person := seedUser(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	accounts := nokkuv1connect.NewTargetAccountServiceClient(admin)
	account, err := accounts.AddTargetAccount(ctx, &nokkuv1.AddTargetAccountRequest{
		TargetId: &first.target, Username: new("deploy"),
	})
	require.NoError(t, err)
	grant := &nokkuv1.AddSubjectsRequest{
		Id:         new(account.GetAccount().GetId()),
		Kind:       nokkuv1.SubjectKind_SUBJECT_KIND_USER.Enum(),
		SubjectIds: []string{person.ID},
	}
	_, err = accounts.AddSubjects(ctx, grant)
	require.NoError(t, err)
	principal := nklogin.Principal(person.ID, first.target, "deploy")
	require.Eventually(t, func() bool { return first.lets(principal) }, time.Minute, 10*time.Millisecond,
		"the grant never reached its server")
	fleet.settle(t)

	// What the core does on its own in a window as long as the two below.
	before := commits()
	fleet.settle(t)
	idle := commits() - before

	fleet.syncs.Store(0)
	before = commits()
	revoked := time.Now()
	_, err = accounts.RemoveSubjects(ctx, &nokkuv1.RemoveSubjectsRequest{
		Id: grant.Id, Kind: grant.Kind, SubjectIds: grant.GetSubjectIds(),
	})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return !first.lets(principal) }, 5*time.Minute, time.Millisecond,
		"the revoke never reached its server")
	landed := time.Since(revoked)
	quiet := fleet.settle(t).Sub(revoked)
	revokeSyncs, revokeCommits := fleet.syncs.Swap(0), commits()-before

	before = commits()
	round := each("heartbeat", (*fakeDaemon).heartbeat)
	fleet.settle(t)
	beatSyncs, beatCommits := fleet.syncs.Load(), commits()-before

	t.Logf("%d daemons, enrolled in %s, connected in %s", n, enrolled.Round(time.Millisecond),
		connected.Round(time.Millisecond))
	t.Logf("one revoke on one server: there after %s, %d syncs, %d database transactions, quiet after %s",
		landed.Round(time.Millisecond), revokeSyncs, revokeCommits, quiet.Round(time.Millisecond))
	t.Logf("one round of heartbeats, sent in %s: %d syncs, %d database transactions",
		round.Round(time.Millisecond), beatSyncs, beatCommits)
	t.Logf("an idle window of the same length: %d database transactions", idle)
}
