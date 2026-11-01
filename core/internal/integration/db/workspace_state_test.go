//go:build integration

package db_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// Daemons read the idle timeout from the settings, a change reaches them at
// once.
func TestStateVersionBumpsOnSettings(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	conn := listen(t, c)
	before := stateVersion(t, c, f.ws)

	asOwner(t, c, f, func(q *db.Queries) error {
		_, err := q.UpdateWorkspace(t.Context(), &db.UpdateWorkspaceParams{
			Settings: &nokkuv1.WorkspaceSettings{SessionIdleTimeout: durationpb.New(15 * time.Minute)},
		})
		return err
	})

	waitNotify(t, conn, f.ws)
	after := stateVersion(t, c, f.ws)
	require.Greater(t, after, before, "an idle timeout change must bump the version")

	// Daemons read nothing else there, so nothing else makes them sync.
	asOwner(t, c, f, func(q *db.Queries) error {
		_, err := q.UpdateWorkspace(t.Context(), &db.UpdateWorkspaceParams{
			Settings: &nokkuv1.WorkspaceSettings{
				SessionIdleTimeout: durationpb.New(15 * time.Minute),
				EnforceSso:         new(true),
			},
		})
		return err
	})
	require.Equal(t, after, stateVersion(t, c, f.ws), "another settings change moved the version")
}
