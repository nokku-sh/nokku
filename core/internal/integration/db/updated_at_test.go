//go:build integration

package db_test

import (
	"testing"
	"time"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// An edit moves updated_at. What a host reports about itself is no edit, or every sync would look like one.
func TestEditsMoveUpdatedAt(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	var serviceAccount string
	asOwner(t, c, f, func(q *db.Queries) (err error) {
		serviceAccount, err = q.CreateServiceAccount(t.Context(), &db.CreateServiceAccountParams{
			Name: "ci", Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
		})
		return err
	})
	updatedAt := func(table, id string) (at time.Time) {
		t.Helper()
		err := c.sysPool.QueryRow(t.Context(), `SELECT updated_at FROM `+table+` WHERE id = $1`, id).Scan(&at)
		if err != nil {
			t.Fatalf("read %s.updated_at: %v", table, err)
		}
		return at
	}

	for _, edit := range []struct {
		table, id string
		run       func(q *db.Queries) error
	}{
		{"teams", f.team, func(q *db.Queries) error {
			_, err := q.UpdateTeam(t.Context(), &db.UpdateTeamParams{TeamID: f.team, Name: new("renamed")})
			return err
		}},
		{"targets", f.target, func(q *db.Queries) error {
			_, err := q.UpdateTarget(t.Context(), &db.UpdateTargetParams{TargetID: f.target, Name: new("renamed")})
			return err
		}},
		{"daemons", f.daemon, func(q *db.Queries) error {
			_, err := q.UpdateDaemon(t.Context(), &db.UpdateDaemonParams{
				DaemonID: f.daemon, Status: nokkuv1.DaemonStatus_DAEMON_STATUS_REJECTED,
			})
			return err
		}},
		{"service_accounts", serviceAccount, func(q *db.Queries) error {
			_, err := q.UpdateServiceAccount(t.Context(), &db.UpdateServiceAccountParams{
				ServiceAccountID: serviceAccount, Name: new("renamed"),
			})
			return err
		}},
		{"ssh_cas", f.ca, func(q *db.Queries) error {
			_, err := q.UpdateCA(t.Context(), &db.UpdateCAParams{SourceAddress: new("10.0.0.0/8")})
			return err
		}},
	} {
		before := updatedAt(edit.table, edit.id)
		asOwner(t, c, f, edit.run)
		if after := updatedAt(edit.table, edit.id); !after.After(before) {
			t.Errorf("an edit of %s left updated_at at %s", edit.table, after)
		}
	}

	daemon, target := updatedAt("daemons", f.daemon), updatedAt("targets", f.target)
	asOwner(t, c, f, func(q *db.Queries) error {
		if err := q.MarkDaemonSeen(t.Context(), f.daemon); err != nil {
			return err
		}
		if err := q.UpdateDaemonVersion(t.Context(), &db.UpdateDaemonVersionParams{
			DaemonID: f.daemon, Version: "1.0.0",
		}); err != nil {
			return err
		}
		if err := q.UpdateTargetReport(t.Context(), &db.UpdateTargetReportParams{
			TargetID: f.target, Metadata: []byte(`{"os": "linux"}`), Endpoints: []string{"10.0.0.5:4022"},
		}); err != nil {
			return err
		}
		if err := q.ReportManualSync(t.Context(), &db.ReportManualSyncParams{
			TargetID: f.target, Endpoints: []string{"10.0.0.6:22"},
		}); err != nil {
			return err
		}
		return q.TouchTargetSync(t.Context(), f.target)
	})
	if d, tg := updatedAt("daemons", f.daemon), updatedAt("targets", f.target); !d.Equal(daemon) || !tg.Equal(target) {
		t.Errorf("a report moved updated_at: daemon %s to %s, target %s to %s", daemon, d, target, tg)
	}
}
