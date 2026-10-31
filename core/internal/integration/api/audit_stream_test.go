//go:build integration

package api_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// The secret goes out as a header or a signature, so it stays with the URL it was entered for.
func TestAuditStreamSecretStaysWithItsURL(t *testing.T) {
	cfg, srv := enterprise(t)
	owner := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER),
	)
	streams := nokkuv1connect.NewAuditStreamServiceClient(
		connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), owner),
	)
	created, err := streams.CreateAuditStream(t.Context(), &nokkuv1.CreateAuditStreamRequest{
		Kind:   nokkuv1.AuditStreamKind_AUDIT_STREAM_KIND_SPLUNK.Enum(),
		Url:    new("https://splunk.example.com/services/collector/event"),
		Secret: new("hec-token-1"),
	})
	require.NoError(t, err)
	id := created.GetStream().GetId()
	t.Cleanup(func() {
		_, _ = streams.DeleteAuditStream(context.WithoutCancel(t.Context()), &nokkuv1.DeleteAuditStreamRequest{Id: &id})
	})

	url := new("https://attacker.example.com/collector")
	_, err = streams.UpdateAuditStream(t.Context(), masked(&nokkuv1.UpdateAuditStreamRequest{Id: &id, Url: url}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "a new URL without the secret: %v", err)
	_, err = streams.UpdateAuditStream(t.Context(),
		masked(&nokkuv1.UpdateAuditStreamRequest{Id: &id, Url: url, Secret: new("hec-token-2")}))
	require.NoError(t, err, "a new URL with its secret")
	_, err = streams.UpdateAuditStream(t.Context(), masked(&nokkuv1.UpdateAuditStreamRequest{Id: &id, Url: url}))
	require.NoError(t, err, "the same URL keeps the stored secret")
	_, err = streams.UpdateAuditStream(
		t.Context(),
		masked(&nokkuv1.UpdateAuditStreamRequest{Id: &id, Enabled: new(false)}),
	)
	require.NoError(t, err, "a toggle needs no secret")
}

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
			id := uuid.NewV7().String()
			secret, err := cfg.Keyset.Seal(audit.SecretAAD(ws, id), []byte("stream-secret"))
			if err != nil {
				return err
			}
			if _, err := q.CreateAuditStream(t.Context(), &db.CreateAuditStreamParams{
				ID:     id,
				Kind:   audit.StreamWebhook,
				URL:    url,
				Secret: secret,
			}); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return nil
	})

	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.WithoutCancel(t.Context())
		_, _ = owner.Exec(ctx, "DELETE FROM audit_streams WHERE id = ANY($1)", ids)
		_ = owner.Close(ctx)
	})
	// An event old enough to pass the stream's settle window, and cursors from before it.
	_, err = owner.Exec(t.Context(), `
		UPDATE audit_streams SET cursor_ts = NOW() - INTERVAL '1 minute' WHERE id = ANY($1);
		INSERT INTO audit.audit_logs (workspace_id, action, ok, timestamp)
		VALUES ($2, 'StreamProbe', TRUE, NOW() - INTERVAL '30 seconds');
	`, pgx.QueryExecModeSimpleProtocol, ids, ws)
	require.NoError(t, err)

	_, err = audit.New(t.Context(), cfg.Conn, cfg.Keyset, cfg.Entitlements)
	require.NoError(t, err)

	select {
	case open := <-got:
		assert.True(t, open, "the fast stream waited until the slow one gave up")
	case <-time.After(25 * time.Second):
		t.Fatal("the fast stream got nothing")
	}
}

// A stream whose secret does not open fails on its own. The streams of every other workspace keep sending.
func TestAnUnreadableStreamSecretStopsNoOtherStream(t *testing.T) {
	cfg, _ := enterprise(t)
	broken, good := seedOtherWorkspace(t, cfg), seedWorkspace(t, cfg)

	got := make(chan struct{}, 1)
	siem := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		select {
		case got <- struct{}{}:
		default:
		}
	}))
	t.Cleanup(siem.Close)

	// The broken stream is made first, so it comes first in every list of streams.
	var ids []string
	for _, ws := range []string{broken, good} {
		id := uuid.NewV7().String()
		sealedFor := id
		if ws == broken {
			sealedFor = uuid.NewV7().String()
		}
		secret, err := cfg.Keyset.Seal(audit.SecretAAD(ws, sealedFor), []byte("stream-secret"))
		require.NoError(t, err)
		inWorkspace(t, cfg, ws, func(q *db.Queries) error {
			_, err := q.CreateAuditStream(t.Context(), &db.CreateAuditStreamParams{
				ID: id, Kind: audit.StreamWebhook, URL: siem.URL, Secret: secret,
			})
			return err
		})
		ids = append(ids, id)
	}

	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	t.Cleanup(func() {
		// t.Context is already canceled when cleanups run.
		ctx := context.WithoutCancel(t.Context())
		_, _ = owner.Exec(ctx, "DELETE FROM audit_streams WHERE id = ANY($1)", ids)
		_ = owner.Close(ctx)
	})
	_, err = owner.Exec(t.Context(), `
		UPDATE audit_streams SET cursor_ts = NOW() - INTERVAL '1 minute' WHERE id = ANY($1);
		INSERT INTO audit.audit_logs (workspace_id, action, ok, timestamp)
		VALUES ($2, 'StreamProbe', TRUE, NOW() - INTERVAL '30 seconds'), ($3, 'StreamProbe', TRUE, NOW() - INTERVAL '30 seconds');
	`, pgx.QueryExecModeSimpleProtocol, ids, broken, good)
	require.NoError(t, err)

	_, err = audit.New(t.Context(), cfg.Conn, cfg.Keyset, cfg.Entitlements)
	require.NoError(t, err)

	select {
	case <-got:
	case <-time.After(25 * time.Second):
		t.Fatal("the readable stream sent nothing")
	}
	assert.Eventually(t, func() bool {
		var lastError string
		err := owner.QueryRow(t.Context(), "SELECT last_error FROM audit_streams WHERE id = $1", ids[0]).
			Scan(&lastError)
		return err == nil && lastError != ""
	}, 10*time.Second, 100*time.Millisecond, "the broken stream is not marked as failing")
}
