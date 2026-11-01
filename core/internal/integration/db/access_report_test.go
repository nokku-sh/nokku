//go:build integration

package db_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// u holds the account directly and through the team, the report lists both.
func TestAccessReportListsEveryWayIn(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)

	var rows []*db.ListAccessReportRow
	asOwner(t, c, f, func(q *db.Queries) (err error) {
		if err := q.TouchAccessUsage(
			t.Context(),
			&db.TouchAccessUsageParams{TargetID: f.target, SubjectID: f.u},
		); err != nil {
			return err
		}
		rows, err = q.ListAccessReport(t.Context())
		return err
	})

	require.Len(t, rows, 2, "want the direct grant and the team grant")
	vias := map[string]bool{}
	for _, r := range rows {
		vias[r.Via] = true
		require.Equal(t, f.u, r.SubjectID)
		require.Equal(t, "deploy", r.Username)
		require.Equal(t, "t", r.Target)
		require.NotNil(t, r.LastCertAt, "a certificate just now left no time")
		require.False(t, r.Stale, "a certificate just now counts as stale")
	}
	require.Equal(t, map[string]bool{"": true, "team": true}, vias)
}
