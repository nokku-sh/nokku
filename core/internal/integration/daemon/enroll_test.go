//go:build integration

package daemon_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/daemon"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/namegen"
	"github.com/nokku-sh/nokku/core/internal/ssh"
)

// fixture is a connection plus a context pinned to a fresh workspace.
type fixture struct {
	conn *db.Connection
	ctx  context.Context
}

// enrollToken mints a token in a fresh workspace. tweak adjusts the row.
func enrollToken(t *testing.T, tweak func(*db.CreateJoinTokenParams)) (fixture, string) {
	t.Helper()
	// The connection lives as long as its context, so it gets the test's.
	ctx := t.Context()
	conn, err := db.NewConnection(ctx)
	require.NoError(t, err, "connect")

	var plaintext string
	workspaceID := uuid.NewV7().String()
	pinned := actor.WithWorkspace(ctx, actor.Workspace{ID: workspaceID})
	err = conn.TenantTx(pinned, func(q *db.Queries) error {
		if _, err := q.CreateWorkspace(ctx, &db.CreateWorkspaceParams{
			ID: workspaceID, Slug: uuid.NewV7().String(), Name: "ws", Settings: &nokkuv1.WorkspaceSettings{},
		}); err != nil {
			return err
		}
		// Every workspace has its CA. Enroll and sync read its public keys.
		ca := ssh.NewCA()
		ca.UserPublicKey, ca.HostPublicKey = "pub", "host-pub"
		if _, err := q.CreateCA(ctx, ca); err != nil {
			return err
		}
		params := &db.CreateJoinTokenParams{}
		plaintext, params.TokenHash = crypto.NewToken(crypto.TokenEnroll)
		if tweak != nil {
			tweak(params)
		}
		_, err = q.CreateJoinToken(ctx, params)
		return err
	})
	require.NoError(t, err, "seed token")
	return fixture{conn: conn, ctx: pinned}, plaintext
}

func enroll(t *testing.T, f fixture, in daemon.EnrollInput) (*daemon.Enrolled, error) {
	t.Helper()
	if in.Binding == "" {
		in.Binding = uuid.NewV7().String()
	}
	return daemon.Enroll(f.ctx, f.conn, in)
}

// Parallel enrollments of one machine, a retrying installer, make one daemon.
func TestEnrollSameKeyConcurrently(t *testing.T) {
	f, token := enrollToken(t, nil)
	in := daemon.EnrollInput{Token: token, Binding: uuid.NewV7().String()}

	const n = 8
	ids := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			out, err := daemon.Enroll(f.ctx, f.conn, in)
			errs[i] = err
			if out != nil {
				ids[i] = out.DaemonID
			}
		})
	}
	wg.Wait()

	for i := range n {
		require.NoError(t, errs[i], "enroll %d", i)
		require.Equal(t, ids[0], ids[i], "enroll %d", i)
	}
}

// Twins from one image enroll at once under one hostname. One keeps it, the rest get generated names.
func TestEnrollSameNameConcurrently(t *testing.T) {
	f, token := enrollToken(t, nil)

	const n = 8
	names := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			out, err := enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname("web-1")})
			errs[i] = err
			if out != nil {
				names[i] = out.Name
			}
		})
	}
	wg.Wait()

	for i := range n {
		require.NoError(t, errs[i], "enroll %d", i)
	}
	assert.Contains(t, names, "web-1")
	slices.Sort(names)
	assert.Len(t, slices.Compact(names), n, "two daemons got one name")
}

// A fleet of cloud hosts with default names outgrows the word pairs. The names then carry a number.
func TestEnrollPastTheWordPairs(t *testing.T) {
	f, token := enrollToken(t, nil)

	// 300,000 draws leave no pair out, there are under 12,000.
	pairs := make(map[string]bool)
	for range 300_000 {
		pairs[namegen.Generate()] = true
	}
	err := f.conn.TenantTx(f.ctx, func(q *db.Queries) error {
		for name := range pairs {
			if _, err := q.CreateTarget(f.ctx, &db.CreateTargetParams{Name: name}); err != nil {
				return err
			}
		}
		return nil
	})
	require.NoError(t, err, "take every word pair")

	for i := range 20 {
		out, err := enroll(t, f, daemon.EnrollInput{Token: token, ReqMetadata: hostname("ip-10-0-12-34")})
		require.NoError(t, err, "enroll %d", i)
		assert.False(t, pairs[out.Name], "enroll %d took the name %q twice", i, out.Name)
	}
}

// A known machine re-enrolls without consulting the quota, a new one does.
func TestEnrollQuotaOnlyForNewMachines(t *testing.T) {
	f, token := enrollToken(t, nil)
	full := errors.New("at cap")
	calls := 0
	in := daemon.EnrollInput{
		Token:   token,
		Binding: uuid.NewV7().String(),
		CanCreate: func(context.Context, string) error {
			calls++
			return nil
		},
	}
	_, err := enroll(t, f, in)
	require.NoError(t, err, "first enroll")

	in.CanCreate = func(context.Context, string) error { return full }
	_, err = enroll(t, f, in)
	require.NoError(t, err, "re-enroll at cap")

	in.Binding = ""
	_, err = enroll(t, f, in)
	require.ErrorIs(t, err, full, "new machine at cap")
	require.Equal(t, 1, calls, "quota calls on the first enroll")
}

// Only new daemons spend uses. A one-use token lets its machine re-enroll and
// turns the next one away.
func TestEnrollMaxUses(t *testing.T) {
	f, token := enrollToken(t, func(p *db.CreateJoinTokenParams) {
		p.MaxUses = new(int32(1))
	})
	first := daemon.EnrollInput{Token: token, Binding: uuid.NewV7().String()}
	_, err := enroll(t, f, first)
	require.NoError(t, err, "first enroll")
	_, err = enroll(t, f, first)
	require.NoError(t, err, "re-enroll with a spent token")
	_, err = enroll(t, f, daemon.EnrollInput{Token: token})
	require.ErrorIs(t, err, daemon.ErrEnrollToken, "second machine")
}

func TestEnrollExpiredToken(t *testing.T) {
	f, token := enrollToken(t, func(p *db.CreateJoinTokenParams) {
		p.ExpiresAt = new(time.Now().Add(-time.Minute))
	})
	_, err := enroll(t, f, daemon.EnrollInput{Token: token})
	require.ErrorIs(t, err, daemon.ErrEnrollToken)
}

func TestEnrollAutoApprove(t *testing.T) {
	f, pending := enrollToken(t, nil)
	out, err := enroll(t, f, daemon.EnrollInput{Token: pending})
	require.NoError(t, err, "plain token")
	require.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING, out.Status, "plain token")

	f, approved := enrollToken(t, func(p *db.CreateJoinTokenParams) { p.AutoApprove = true })
	out, err = enroll(t, f, daemon.EnrollInput{Token: approved})
	require.NoError(t, err, "auto-approve token")
	require.Equal(t, nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED, out.Status, "auto-approve token")
}

func TestEnrollRejectsBadToken(t *testing.T) {
	f, token := enrollToken(t, nil)
	quota := false
	_, err := enroll(t, f, daemon.EnrollInput{
		Token: token + "x",
		CanCreate: func(context.Context, string) error {
			quota = true
			return nil
		},
	})
	require.ErrorIs(t, err, daemon.ErrEnrollToken)
	require.False(t, quota, "quota checked before the token verified")
}

// A server with a daemon is one resource toward the cap.
func TestEnrolledServerCountsOnce(t *testing.T) {
	f, token := enrollToken(t, nil)
	ws, _ := actor.WorkspaceFromContext(f.ctx)
	count := func() int64 {
		t.Helper()
		n, err := f.conn.Sys().CountWorkspaceResources(f.ctx, ws.ID)
		require.NoError(t, err)
		return n
	}

	before := count()
	_, err := enroll(t, f, daemon.EnrollInput{Token: token})
	require.NoError(t, err)
	assert.Equal(t, before+1, count())
}
