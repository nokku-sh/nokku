package main

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/nktoken"
)

func TestCheckAPIURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		url string
		ok  bool
	}{
		{"https://acme.nokku.sh", true},
		{"https://10.0.0.5:8443", true},
		{"http://localhost:3000", true},
		{"http://127.0.0.1:3000", true},
		{"http://[::1]:3000", true},
		{"http://nokku.example.com", false},
		{"http://10.0.0.5:3000", false},
		{"http://localhost.example.com", false},
		{"nokku.example.com", false},
		{"ftp://localhost", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.ok, checkAPIURL(tt.url) == nil, "accepted is wrong for %q", tt.url)
		})
	}
}

func TestCheckEnrollToken(t *testing.T) {
	t.Parallel()
	token := nktoken.New("enroll")
	require.NoError(t, checkEnrollToken(token))
	for _, bad := range []string{
		// The old format.
		"0199f3a1-7c2e-7d4b-9a10-3f2c1b0e8d7a_" + strings.Repeat("a", 43),
		nktoken.New("invite"),
		token[:len(token)-1],
		"nk_enroll_",
	} {
		assert.ErrorContains(t, checkEnrollToken(bad), "nk_enroll_", "%q", bad)
	}
}

func TestAwaitIdle(t *testing.T) {
	// Runs awaitIdle after an upgrade, and reads when it answered.
	upgrade := func(ctx context.Context, idle func() bool) (answered <-chan bool) {
		upgraded := make(chan os.Signal, 1)
		upgraded <- syscall.SIGUSR1
		out := make(chan bool, 1)
		go func() { out <- awaitIdle(ctx, upgraded, idle) }()
		return out
	}

	t.Run("an idle host restarts at once", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			start := time.Now()
			assert.True(t, <-upgrade(t.Context(), func() bool { return true }))
			assert.Zero(t, time.Since(start))
		})
	})

	t.Run("waits for the last connection", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var idle atomic.Bool
			answered := upgrade(t.Context(), idle.Load)
			time.Sleep(10 * time.Minute)
			synctest.Wait()
			assert.Empty(t, answered, "restarted over an open session")

			idle.Store(true)
			time.Sleep(upgradeTick)
			synctest.Wait()
			assert.True(t, <-answered)
		})
	})

	t.Run("a session can't hold it off past the limit", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			start := time.Now()
			assert.True(t, <-upgrade(t.Context(), func() bool { return false }))
			assert.Equal(t, upgradeWait, time.Since(start))
		})
	})

	t.Run("a stop during the wait is no restart", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, stop := context.WithCancel(t.Context())
			answered := upgrade(ctx, func() bool { return false })
			time.Sleep(time.Minute)
			stop()
			assert.False(t, <-answered)
		})
	})

	t.Run("no upgrade, no restart", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, stop := context.WithCancel(t.Context())
			answered := make(chan bool, 1)
			go func() { answered <- awaitIdle(ctx, make(chan os.Signal), func() bool { return true }) }()
			synctest.Wait()
			assert.Empty(t, answered, "restarted with no upgrade")
			stop()
			assert.False(t, <-answered)
		})
	})
}
