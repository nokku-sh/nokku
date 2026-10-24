//go:build integration

package api_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// A destination that hangs must not hold back the streams behind it.
func TestSlowAuditStreamHoldsUpNoOther(t *testing.T) {
	cfg, _ := enterprise(t)
	ws := seedWorkspace(t, cfg)

	slowDone := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	slow := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// Only a drained body lets the server see the client give up.
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-release:
		}
		once.Do(func() { close(slowDone) })
	}))
	t.Cleanup(slow.Close)
	t.Cleanup(func() { close(release) })

	// true when the event arrived while the slow destination still held its request.
	got := make(chan bool, 1)
	fast := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		open := true
		select {
		case <-slowDone:
			open = false
		default:
		}
		// Only the first batch counts, later ones must not block the handler.
		select {
		case got <- open:
		default:
		}
	}))
	t.Cleanup(fast.Close)

	// The slow stream is made first, so a loop that sends one stream after another reaches it first.
	var ids []string
	inWorkspace(t, cfg, ws, func(q *db.Queries) error {
		for _, url := range []string{slow.URL, fast.URL} {
			st, err := q.CreateAuditStream(t.Context(), &db.CreateAuditStreamParams{
				Kind:   audit.StreamWebhook,
				URL:    url,
				Secret: []byte("stream-secret"),
			})
			if err != nil {
				return err
			}
			ids = append(ids, st.ID)
		}
		return nil
	})

	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = owner.Exec(t.Context(), "DELETE FROM audit_streams WHERE id = ANY($1)", ids)
		_ = owner.Close(t.Context())
	})
	// An event old enough to pass the stream's settle window, and cursors from before it.
	_, err = owner.Exec(t.Context(), `
		UPDATE audit_streams SET cursor_ts = NOW() - INTERVAL '1 minute' WHERE id = ANY($1);
		INSERT INTO audit.audit_logs (workspace_id, action, ok, timestamp)
		VALUES ($2, 'StreamProbe', TRUE, NOW() - INTERVAL '30 seconds');
	`, pgx.QueryExecModeSimpleProtocol, ids, ws)
	require.NoError(t, err)

	_, err = audit.New(t.Context(), cfg.Conn, cfg.Entitlements)
	require.NoError(t, err)

	select {
	case open := <-got:
		assert.True(t, open, "the fast stream waited until the slow one gave up")
	case <-time.After(25 * time.Second):
		t.Fatal("the fast stream got nothing")
	}
}
