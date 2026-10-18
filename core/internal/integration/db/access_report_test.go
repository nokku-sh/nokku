//go:build integration

package db_test

import (
	"testing"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// The fixture's user holds the account directly and through the team, the report lists both ways.
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

	if len(rows) != 2 {
		t.Fatalf("want the direct grant and the team grant, got %d rows", len(rows))
	}
	vias := map[string]bool{}
	for _, r := range rows {
		vias[r.Via] = true
		if r.SubjectID != f.u || r.Username != "deploy" || r.Target != "t" {
			t.Fatalf("unexpected row %+v", r)
		}
		if r.LastCertAt == nil || r.Stale {
			t.Fatalf("a certificate just now: last %v, stale %v", r.LastCertAt, r.Stale)
		}
	}
	if !vias[""] || !vias["team"] {
		t.Fatalf("ways in = %v, want direct and the team", vias)
	}
}
