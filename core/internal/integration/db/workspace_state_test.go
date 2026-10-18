//go:build integration

package db_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// Daemons read the idle timeout from the workspace settings, so a change there must reach them at once.
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
	if after <= before {
		t.Fatalf("idle timeout change: version %d -> %d, want a bump", before, after)
	}

	// Daemons read nothing else from the settings, so nothing else makes them sync.
	asOwner(t, c, f, func(q *db.Queries) error {
		_, err := q.UpdateWorkspace(t.Context(), &db.UpdateWorkspaceParams{
			Settings: &nokkuv1.WorkspaceSettings{
				SessionIdleTimeout: durationpb.New(15 * time.Minute),
				EnforceSso:         new(true),
			},
		})
		return err
	})
	if again := stateVersion(t, c, f.ws); again != after {
		t.Fatalf("another settings change: version %d -> %d, want none", after, again)
	}
}
