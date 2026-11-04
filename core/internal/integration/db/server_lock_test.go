//go:build integration

package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// A second core waits until the first one stops, then takes over.
func TestOneCoreAtATime(t *testing.T) {
	first, stopFirst := context.WithCancel(t.Context())
	defer stopFirst()
	require.NoError(t, db.HoldServerLock(t.Context(), first, func() {}))

	second, stopSecond := context.WithCancel(t.Context())
	defer stopSecond()
	took := make(chan error, 1)
	go func() { took <- db.HoldServerLock(t.Context(), second, func() {}) }()
	select {
	case err := <-took:
		t.Fatalf("a second core started next to the first: %v", err)
	case <-time.After(500 * time.Millisecond):
	}

	stopFirst()
	select {
	case err := <-took:
		require.NoError(t, err, "the second core did not take over")
	case <-time.After(5 * time.Second):
		t.Fatal("the second core still waits after the first stopped")
	}
}

// A signal ends the wait, a core that never started holds nothing.
func TestAWaitingCoreStopsOnItsSignal(t *testing.T) {
	hold, stop := context.WithCancel(t.Context())
	defer stop()
	require.NoError(t, db.HoldServerLock(t.Context(), hold, func() {}))

	wait, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	require.Error(t, db.HoldServerLock(wait, t.Context(), func() {}), "the wait outlived its signal")
}

// lockSessions counts the sessions that hold the server lock, or wait for it.
func lockSessions(t *testing.T, owner *pgx.Conn, granted bool) int {
	t.Helper()
	var n int
	require.NoError(t, owner.QueryRow(t.Context(), `
		SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
		WHERE l.locktype = 'advisory' AND l.granted = $1 AND a.application_name = $2`,
		granted, db.ServerLockApp).Scan(&n))
	return n
}

// terminateLockHolder waits for the session to end, or it still counts as holding.
func terminateLockHolder(t *testing.T, owner *pgx.Conn) {
	t.Helper()
	var n int
	require.NoError(t, owner.QueryRow(t.Context(), `
		SELECT count(pg_terminate_backend(l.pid, 5000)) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
		WHERE l.locktype = 'advisory' AND l.granted AND a.application_name = $1`,
		db.ServerLockApp).Scan(&n))
	require.Equal(t, 1, n, "no session held the server lock")
}

func ownerConn(t *testing.T) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(context.WithoutCancel(t.Context())) })
	return conn
}

// A database restart ends the lock's session, the core takes it again.
func TestTheServerLockComesBack(t *testing.T) {
	owner := ownerConn(t)
	hold, stop := context.WithCancel(t.Context())
	defer stop()
	lost := make(chan struct{}, 1)
	require.NoError(t, db.HoldServerLock(t.Context(), hold, func() { lost <- struct{}{} }))

	terminateLockHolder(t, owner)
	require.Eventually(t, func() bool { return lockSessions(t, owner, true) == 1 },
		5*time.Second, 20*time.Millisecond, "the core did not take the lock again")
	select {
	case <-lost:
		t.Fatal("the core stopped though nobody else held the lock")
	default:
	}
}

// A core that waited in line gets the lock when the holder's session ends.
// The holder must stop then, or two cores run.
func TestALostServerLockStopsTheCore(t *testing.T) {
	owner := ownerConn(t)
	first, stopFirst := context.WithCancel(t.Context())
	defer stopFirst()
	lost := make(chan struct{}, 1)
	require.NoError(t, db.HoldServerLock(t.Context(), first, func() { lost <- struct{}{} }))

	second, stopSecond := context.WithCancel(t.Context())
	defer stopSecond()
	took := make(chan error, 1)
	go func() { took <- db.HoldServerLock(t.Context(), second, func() {}) }()
	require.Eventually(t, func() bool { return lockSessions(t, owner, false) == 1 },
		5*time.Second, 20*time.Millisecond, "the second core never waited")

	terminateLockHolder(t, owner)
	select {
	case err := <-took:
		require.NoError(t, err, "the waiting core did not get the lock")
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting core still waits")
	}
	select {
	case <-lost:
	case <-time.After(10 * time.Second):
		t.Fatal("the first core kept running without the lock")
	}
}

// A core that cannot log in again stops, the next one may hold the lock by then.
func TestALockThatStaysAwayStopsTheCore(t *testing.T) {
	owner := ownerConn(t)
	hold, stop := context.WithCancel(t.Context())
	defer stop()
	lost := make(chan struct{}, 1)
	require.NoError(t, db.HoldServerLock(t.Context(), hold, func() { lost <- struct{}{} }))

	t.Setenv("PGPASSWORD", "rotated")
	terminateLockHolder(t, owner)
	select {
	case <-lost:
		t.Fatal("the core stopped before it tried for a minute")
	case <-time.After(50 * time.Second):
	}
	select {
	case <-lost:
	case <-time.After(20 * time.Second):
		t.Fatal("the core kept running without the lock")
	}
}
