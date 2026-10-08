//go:build integration

package db_test

import (
	"slices"
	"testing"
	"time"

	"github.com/nokku-sh/nokku/internal/db"
)

func TestListAuditLogsFilters(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)

	for _, e := range []struct {
		action  string
		ok      bool
		details string
	}{
		{"DeleteTarget", true, `{}`},
		{"UpdateWorkspace", true, `{}`},
		{"UpdateUserRole", false, `{"code":"permission_denied"}`},
		{"CreateTarget", false, `{"code":"invalid_argument"}`},
		{"LoginDenied", false, `{}`},
	} {
		if err := c.Sys().InsertAuditLog(t.Context(), &db.InsertAuditLogParams{
			WorkspaceID: f.ws,
			ActorID:     f.owner,
			ActorKind:   "user",
			Action:      e.action,
			Ok:          e.ok,
			Details:     []byte(e.details),
		}); err != nil {
			t.Fatalf("insert %s: %v", e.action, err)
		}
	}

	cases := map[string]struct {
		outcome string
		actions []string
		want    []string
	}{
		"succeeded": {outcome: "succeeded", want: []string{"DeleteTarget", "UpdateWorkspace"}},
		"failed includes deny": {
			outcome: "failed",
			want:    []string{"CreateTarget", "LoginDenied", "UpdateUserRole"},
		},
		"denied only": {outcome: "denied", want: []string{"LoginDenied", "UpdateUserRole"}},
		"exact name":  {actions: []string{"UpdateWorkspace"}, want: []string{"UpdateWorkspace"}},
		"prefix with star": {
			actions: []string{"Update*"},
			want:    []string{"UpdateUserRole", "UpdateWorkspace"},
		},
		"mixed": {
			actions: []string{"Delete*", "CreateTarget"},
			want:    []string{"CreateTarget", "DeleteTarget"},
		},
	}

	start, end := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := &db.ListAuditLogsParams{
				Actions:   tc.actions,
				StartDate: &start,
				EndDate:   &end,
				Limit:     100,
			}
			if tc.outcome != "" {
				p.Outcome = &tc.outcome
			}
			var got []string
			asOwner(t, c, f, func(q *db.Queries) error {
				rows, err := q.ListAuditLogs(t.Context(), p)
				for _, r := range rows {
					got = append(got, r.Action)
				}
				return err
			})
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
