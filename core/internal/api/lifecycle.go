package api

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/app"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/email"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
)

// lapsedKeepDays is how long a lapsed hosted workspace waits for its owner.
const lapsedKeepDays = 180

const (
	lapseWait lapseAction = iota
	lapseWarn
	lapseDelete
)

// The days before an event that its owner gets a mail, the earliest first.
var (
	trialReminders = []int32{7, 3}
	// The trial reminders name the deletion date, so one warning is enough.
	trialDeletionWarnings = []int32{7}
	paidDeletionWarnings  = []int32{30, 7}
)

type lapseAction int

// runLifecycle mails owners and deletes lapsed workspaces to free their names.
func runLifecycle(ctx context.Context, cfg *app.Config) {
	tick := time.Tick(time.Hour)
	for {
		remindTrials(ctx, cfg)
		purgeLapsed(ctx, cfg)
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
	}
}

// A reminder is marked only once it went out, so a mail outage retries it.
func remindTrials(ctx context.Context, cfg *app.Config) {
	// Without SMTP a mail goes nowhere, and marking it would skip it for good.
	if !cfg.Email.HasSMTP() {
		return
	}
	rows, err := cfg.Conn.Sys().ListTrialsEnding(ctx, trialReminders[0])
	if err != nil {
		slog.Error("listing trials that end soon failed", "error", err)
		return
	}
	for _, row := range rows {
		due := reminderDue(time.Until(row.TrialEnd), row.TrialReminder, trialReminders)
		if due == 0 {
			continue
		}
		err := cfg.Email.SendTrialEndingEmail(ctx, email.TrialEnding{
			UserID:     row.OwnerID,
			Email:      row.OwnerEmail,
			Workspace:  row.WorkspaceName,
			BillingURL: billingPage(cfg.Tenant.BaseURL(row.Slug)),
			Next:       nextReminder(due, trialReminders),
			Ends:       row.TrialEnd,
			Deleted:    entitlement.HoldEnd(row.TrialEnd),
		})
		if err != nil && !errors.Is(err, email.ErrCooldown) {
			slog.Warn("trial reminder not sent", "error", err, "workspace_id", row.WorkspaceID)
			continue
		}
		if err := cfg.Conn.Sys().SetTrialReminder(ctx, &db.SetTrialReminderParams{
			Days:        due,
			WorkspaceID: row.WorkspaceID,
		}); err != nil {
			slog.Warn("trial reminder not recorded", "error", err, "workspace_id", row.WorkspaceID)
		}
	}
}

func purgeLapsed(ctx context.Context, cfg *app.Config) {
	rows, err := cfg.Conn.Sys().ListLapsedWorkspaces(ctx)
	if err != nil {
		slog.Error("listing lapsed workspaces failed", "error", err)
		return
	}
	for _, row := range rows {
		lic := &row.WorkspaceLicense
		mails := cfg.Email.HasSMTP() && row.OwnerEmail != nil
		step, due, deleteAt := lapseStep(lic, mails, time.Now())
		switch step {
		case lapseWait:
		case lapseWarn:
			warnDeletion(ctx, cfg, row, due, deleteAt)
		case lapseDelete:
			ws := actor.Workspace{ID: lic.WorkspaceID, Slug: row.Slug}
			if err := deleteWorkspace(ctx, cfg, ws); err != nil {
				slog.Error("deleting a lapsed workspace failed", "error", err, "workspace_id", ws.ID)
				continue
			}
			slog.Info("deleted a workspace that stopped paying",
				"workspace_id", ws.ID, "slug", ws.Slug, "trial", entitlement.OnTrial(lic))
		}
	}
}

// With mail, nobody goes before the last warning, which gets its full days.
func lapseStep(lic *db.WorkspaceLicense, mails bool, now time.Time) (lapseAction, int32, time.Time) {
	ends := deletionDate(lic)
	if ends == nil {
		return lapseWait, 0, time.Time{}
	}
	deleteAt, last := *ends, lastWarning(lic)

	left := deleteAt.Sub(now)
	if due := reminderDue(left, lic.DeletionWarning, deletionWarnings(lic)); due != 0 && mails {
		if due == last {
			deleteAt = later(deleteAt, now.Add(days(last)))
		}
		return lapseWarn, due, deleteAt
	}
	if left > 0 {
		return lapseWait, 0, deleteAt
	}
	return lapseDelete, 0, deleteAt
}

// deletionDate is nil while the workspace runs or its key never expires, a late last warning pushes it out.
func deletionDate(lic *db.WorkspaceLicense) *time.Time {
	ended := entitlement.Ended(lic)
	if ended == nil {
		return nil
	}
	// A trial goes when its hold ends, a key that ran out waits half a year.
	ends := ended.Add(days(lapsedKeepDays))
	if entitlement.OnTrial(lic) {
		ends = entitlement.HoldEnd(*ended)
	}
	if last := lastWarning(lic); lic.DeletionWarning == last && lic.DeletionWarnedAt != nil {
		ends = later(ends, lic.DeletionWarnedAt.Add(days(last)))
	}
	return &ends
}

func deletionWarnings(lic *db.WorkspaceLicense) []int32 {
	if entitlement.OnTrial(lic) {
		return trialDeletionWarnings
	}
	return paidDeletionWarnings
}

func lastWarning(lic *db.WorkspaceLicense) int32 {
	w := deletionWarnings(lic)
	return w[len(w)-1]
}

// billingPage is on the workspace host, the hosted root host has no workspace.
func billingPage(baseURL string) string {
	return baseURL + "/settings/billing"
}

func warnDeletion(
	ctx context.Context,
	cfg *app.Config,
	row *db.ListLapsedWorkspacesRow,
	due int32,
	deleteAt time.Time,
) {
	lic := &row.WorkspaceLicense
	err := cfg.Email.SendDeletionWarningEmail(ctx, email.DeletionWarning{
		UserID:     *row.OwnerID,
		Email:      *row.OwnerEmail,
		Workspace:  row.WorkspaceName,
		Slug:       row.Slug,
		BillingURL: billingPage(cfg.Tenant.BaseURL(row.Slug)),
		Trial:      entitlement.OnTrial(lic),
		Next:       nextReminder(due, deletionWarnings(lic)),
		Ended:      *entitlement.Ended(lic),
		Deleted:    deleteAt,
	})
	if err != nil && !errors.Is(err, email.ErrCooldown) {
		slog.Warn("deletion warning not sent", "error", err, "workspace_id", lic.WorkspaceID)
		return
	}
	if err := cfg.Conn.Sys().SetDeletionWarning(ctx, &db.SetDeletionWarningParams{
		Days:        due,
		WorkspaceID: lic.WorkspaceID,
	}); err != nil {
		slog.Warn("deletion warning not recorded", "error", err, "workspace_id", lic.WorkspaceID)
	}
}

// reminderDue is the mail due, 0 for none. A late run sends only the latest.
func reminderDue(left time.Duration, sent int32, schedule []int32) int32 {
	var due int32
	for _, d := range schedule {
		if left <= days(d) {
			due = d
		}
	}
	if due == 0 || (sent != 0 && sent <= due) {
		return 0
	}
	return due
}

func nextReminder(due int32, schedule []int32) int32 {
	i := slices.Index(schedule, due)
	if i < 0 || i == len(schedule)-1 {
		return 0
	}
	return schedule[i+1]
}

func days(n int32) time.Duration {
	return time.Duration(n) * 24 * time.Hour
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
