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
func TestTheIdleTimeoutNotifies(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	w := watch(t, c, f.ws)

	asOwner(t, c, f, func(q *db.Queries) error {
		_, err := q.UpdateWorkspace(t.Context(), &db.UpdateWorkspaceParams{
			Settings: &nokkuv1.WorkspaceSettings{SessionIdleTimeout: durationpb.New(15 * time.Minute)},
		})
		return err
	})

	require.Equal(t, 1, w.seen(t), "an idle timeout change")

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
	require.Zero(t, w.seen(t), "another settings change looked like an access change")
}
