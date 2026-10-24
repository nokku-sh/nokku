//go:build integration

package db_test

import (
	"testing"
	"time"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/ssh"
)

// An edit moves updated_at. What a host reports about itself is no edit, or every sync would look like one.
func TestEditsMoveUpdatedAt(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	ca, err := ssh.NewCA()
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	ca.Name = "ca"
	var caID, serviceAccount string
	asOwner(t, c, f, func(q *db.Queries) error {
		row, err := q.CreateCA(t.Context(), ca)
		if err != nil {
			return err
		}
		caID = row.ID
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
		{"ssh_cas", caID, func(q *db.Queries) error {
			_, err := q.UpdateCA(t.Context(), &db.UpdateCAParams{CaID: caID, Name: new("renamed")})
			return err
		}},
		{"ssh_cas", caID, func(q *db.Queries) error { return q.SetDefaultCA(t.Context(), caID) }},
	} {
		before := updatedAt(edit.table, edit.id)
		asOwner(t, c, f, edit.run)
		if after := updatedAt(edit.table, edit.id); !after.After(before) {
			t.Errorf("an edit of %s left updated_at at %s", edit.table, after)
		}
	}

	daemon, target := updatedAt("daemons", f.daemon), updatedAt("targets", f.target)
	asOwner(t, c, f, func(q *db.Queries) error {
		if err := q.TouchDaemons(t.Context(), []string{f.daemon}); err != nil {
			return err
		}
		if err := q.UpdateDaemonMetadata(t.Context(), &db.UpdateDaemonMetadataParams{
			DaemonID: f.daemon, Metadata: []byte(`{"host": "a"}`),
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
