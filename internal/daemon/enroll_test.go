package daemon

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

// fixture is a connection plus a context pinned to a fresh workspace, the
// way the tenant middleware pins a real request.
type fixture struct {
	conn *db.Connection
	ctx  context.Context
}

// enrollToken connects to the test database and mints an enroll token in a
// fresh workspace, or skips without a database. tweak adjusts the token row.
func enrollToken(t *testing.T, tweak func(*db.CreateWorkspaceTokenParams)) (fixture, string) {
	t.Helper()
	// The connection lives as long as its context, so it gets the test's.
	ctx := t.Context()
	conn, err := db.NewConnection(ctx)
	if err != nil {
		t.Skipf("no test database: %v", err)
	}

	var plaintext string
	workspaceID := uuid.NewV7().String()
	pinned := actor.WithWorkspace(ctx, actor.Workspace{ID: workspaceID})
	err = conn.WithWorkspace(pinned, func(q *db.Queries) error {
		if _, err := q.CreateWorkspace(ctx, &db.CreateWorkspaceParams{
			ID: workspaceID, Slug: uuid.NewV7().String(), Name: "ws", Settings: &nokkuv1.WorkspaceSettings{},
		}); err != nil {
			return err
		}
		params := &db.CreateWorkspaceTokenParams{
			ID:   uuid.NewV7().String(),
			Kind: nokkuv1.TokenKind_TOKEN_KIND_ENROLL,
		}
		token := crypto.NewToken(params.ID)
		params.TokenHash = token.Hash
		plaintext = token.Plaintext
		if tweak != nil {
			tweak(params)
		}
		_, err = q.CreateWorkspaceToken(ctx, params)
		return err
	})
	if err != nil {
		t.Fatalf("seed token: %v", err)
	}
	return fixture{conn: conn, ctx: pinned}, plaintext
}

func enroll(t *testing.T, f fixture, in EnrollInput) (*Enrolled, error) {
	t.Helper()
	if in.Binding == "" {
		in.Binding = uuid.NewV7().String()
	}
	return Enroll(f.ctx, f.conn, in)
}

// Parallel enrollments of one machine, as a retrying installer or a
// double-run playbook produces, must converge on one daemon.
func TestEnrollSameKeyConcurrently(t *testing.T) {
	f, token := enrollToken(t, nil)
	in := EnrollInput{Token: token, Binding: uuid.NewV7().String()}

	const n = 8
	ids := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			out, err := Enroll(f.ctx, f.conn, in)
			errs[i] = err
			if out != nil {
				ids[i] = out.DaemonID
			}
		})
	}
	wg.Wait()

	for i := range n {
		if errs[i] != nil {
			t.Fatalf("enroll %d: %v", i, errs[i])
		}
		if ids[i] != ids[0] {
			t.Fatalf("enroll %d got daemon %s, want %s", i, ids[i], ids[0])
		}
	}
}

// A known machine re-enrolls without consulting the quota, a new one does.
func TestEnrollQuotaOnlyForNewMachines(t *testing.T) {
	f, token := enrollToken(t, nil)
	full := errors.New("at cap")
	calls := 0
	in := EnrollInput{
		Token:   token,
		Binding: uuid.NewV7().String(),
		CanCreate: func(context.Context, string) error {
			calls++
			return nil
		},
	}
	if _, err := enroll(t, f, in); err != nil {
		t.Fatalf("first enroll: %v", err)
	}

	in.CanCreate = func(context.Context, string) error { return full }
	if _, err := enroll(t, f, in); err != nil {
		t.Fatalf("re-enroll at cap: %v", err)
	}

	in.Binding = ""
	if _, err := enroll(t, f, in); !errors.Is(err, full) {
		t.Fatalf("new machine at cap: err = %v, want the quota error", err)
	}
	if calls != 1 {
		t.Fatalf("quota consulted %d times on the first enroll, want 1", calls)
	}
}

// Only new daemons spend uses, so a one-use token still lets its machine
// re-enroll but turns the next machine away.
func TestEnrollMaxUses(t *testing.T) {
	f, token := enrollToken(t, func(p *db.CreateWorkspaceTokenParams) {
		p.MaxUses = new(int32(1))
	})
	first := EnrollInput{Token: token, Binding: uuid.NewV7().String()}
	if _, err := enroll(t, f, first); err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	if _, err := enroll(t, f, first); err != nil {
		t.Fatalf("re-enroll with a spent token: %v", err)
	}
	if _, err := enroll(t, f, EnrollInput{Token: token}); !errors.Is(err, ErrEnrollToken) {
		t.Fatalf("second machine: err = %v, want ErrEnrollToken", err)
	}
}

func TestEnrollExpiredToken(t *testing.T) {
	f, token := enrollToken(t, func(p *db.CreateWorkspaceTokenParams) {
		p.ExpiresAt = new(time.Now().Add(-time.Minute))
	})
	if _, err := enroll(t, f, EnrollInput{Token: token}); !errors.Is(err, ErrEnrollToken) {
		t.Fatalf("err = %v, want ErrEnrollToken", err)
	}
}

func TestEnrollAutoApprove(t *testing.T) {
	f, pending := enrollToken(t, nil)
	out, err := enroll(t, f, EnrollInput{Token: pending})
	if err != nil || out.Status != nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING {
		t.Fatalf("plain token: status %v, err %v, want pending", out.Status, err)
	}

	f, approved := enrollToken(t, func(p *db.CreateWorkspaceTokenParams) { p.AutoApprove = true })
	out, err = enroll(t, f, EnrollInput{Token: approved})
	if err != nil || out.Status != nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED {
		t.Fatalf("auto-approve token: status %v, err %v, want accepted", out.Status, err)
	}
}

func TestEnrollRejectsBadToken(t *testing.T) {
	f, token := enrollToken(t, nil)
	quota := false
	_, err := enroll(t, f, EnrollInput{
		Token: token + "x",
		CanCreate: func(context.Context, string) error {
			quota = true
			return nil
		},
	})
	if !errors.Is(err, ErrEnrollToken) {
		t.Fatalf("err = %v, want ErrEnrollToken", err)
	}
	if quota {
		t.Fatal("quota checked before the token verified")
	}
}

type failingConn struct{}

func (failingConn) WithTx(_ context.Context, fn func(*db.Queries) error) error {
	return fn(db.New(failingTx{}))
}

func (c failingConn) WithWorkspace(ctx context.Context, fn func(*db.Queries) error) error {
	return c.WithTx(ctx, fn)
}

type failingTx struct{ db.DBTX }

func (failingTx) QueryRow(context.Context, string, ...any) pgx.Row { return failingRow{} }

type failingRow struct{}

func (failingRow) Scan(...any) error { return errors.New("connection lost") }

// A database failure is not a verdict on the token.
func TestEnroll_LookupFailureIsNotABadToken(t *testing.T) {
	token := crypto.NewToken(uuid.NewV7().String())
	_, err := Enroll(t.Context(), failingConn{}, EnrollInput{Token: token.Plaintext})
	if err == nil || errors.Is(err, ErrEnrollToken) {
		t.Fatalf("err = %v, want the lookup failure", err)
	}
}
