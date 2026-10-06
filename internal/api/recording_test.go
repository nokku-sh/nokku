package api

import (
	"context"
	"testing"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/recording"
)

// cappedStorage is the SaaS storage cap, a self-hosted instance has none.
type cappedStorage struct{ recording.Limits }

func (cappedStorage) RecordingStorageBytes(context.Context, string) (int64, error) {
	return 10 << 20, nil
}

// An upload over the cap pushes out old recordings, audited, and never a
// recent one.
func TestRecordingEviction(t *testing.T) {
	cfg, srv := newTestAPI(t)
	workspaceID := seedWorkspace(t, cfg)
	_, enrolled := enrollTestDaemon(t, cfg, srv, workspaceID, true)
	daemonID := enrolled.GetId()

	// Two stored recordings and the upload are over the cap by more than one
	// of them.
	const size = 6 << 20
	seed := func(stored bool) string {
		id := uuid.NewV7().String()
		_, err := cfg.Conn.Sys().CreateRecording(t.Context(), &db.CreateRecordingParams{
			ID:          id,
			WorkspaceID: workspaceID,
			DaemonID:    daemonID,
			Username:    "root",
			Key:         recording.NewKey(),
		})
		require.NoError(t, err)
		if stored {
			_, err = cfg.Conn.Sys().SetRecordingComplete(
				t.Context(),
				&db.SetRecordingCompleteParams{ID: id, SizeBytes: size, Complete: true},
			)
			require.NoError(t, err)
		}
		return id
	}
	old, recent, upload := seed(true), seed(true), seed(false)

	// Only the owner role may rewrite a start time.
	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	defer func() { _ = owner.Close(t.Context()) }()
	_, err = owner.Exec(t.Context(), "UPDATE recordings SET started_at = NOW() - INTERVAL '2 days' WHERE id = $1", old)
	require.NoError(t, err)

	ctx := actor.ContextWithPrincipal(
		actor.AnnotateTenant(t.Context(), workspaceID),
		actor.Principal{ID: daemonID, Kind: actor.KindDaemon, WorkspaceID: workspaceID},
	)
	records := recording.New(t.Context(), cfg.Conn, cfg.Storage, cappedStorage{cfg.Entitlements}, cfg.Audit)
	require.NoError(t, records.EvictForBytes(ctx, workspaceID, upload, size))

	_, err = cfg.Conn.Sys().GetRecording(t.Context(), old)
	require.ErrorIs(t, err, pgx.ErrNoRows, "the old recording makes room")
	_, err = cfg.Conn.Sys().GetRecording(t.Context(), recent)
	require.NoError(t, err, "a recording from today stays, even over the cap")

	events, err := cfg.Conn.Sys().ListAuditLogs(t.Context(), &db.ListAuditLogsParams{
		WorkspaceID: &workspaceID,
		Actions:     []string{"RecordingEvicted"},
		Limit:       10,
	})
	require.NoError(t, err)
	require.Len(t, events, 1, "every eviction is audited")
	assert.Equal(t, old, events[0].Target)
	assert.Contains(t, string(events[0].Details), upload, "the event names the upload that needed the room")
}
