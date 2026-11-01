package api

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/billing"
	"github.com/nokku-sh/nokku/core/internal/config"
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
func runLifecycle(ctx context.Context, cfg *config.Config) {
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
func remindTrials(ctx context.Context, cfg *config.Config) {
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
			BillingURL: billing.Page(cfg.Tenant.BaseURL(row.Slug)),
			Next:       nextReminder(due, trialReminders),
			Ends:       row.TrialEnd,
			Deleted:    deleteAfter(entitlement.SourceTrial, row.TrialEnd),
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

func purgeLapsed(ctx context.Context, cfg *config.Config) {
	rows, err := cfg.Conn.Sys().ListLapsedWorkspaces(ctx)
	if err != nil {
		slog.Error("listing lapsed workspaces failed", "error", err)
		return
	}
	for _, row := range rows {
		sub := &row.WorkspaceSubscription
		mails := cfg.Email.HasSMTP() && row.OwnerEmail != nil
		step, due, deleteAt := lapseStep(sub, mails, time.Now())
		switch step {
		case lapseWait:
		case lapseWarn:
			warnDeletion(ctx, cfg, row, due, deleteAt)
		case lapseDelete:
			ws := actor.Workspace{ID: sub.WorkspaceID, Slug: row.Slug}
			if err := deleteWorkspace(ctx, cfg, ws); err != nil {
				slog.Error("deleting a lapsed workspace failed", "error", err, "workspace_id", ws.ID)
				continue
			}
			slog.Info("deleted a workspace that stopped paying",
				"workspace_id", ws.ID, "slug", ws.Slug, "source", sub.Source)
		}
	}
}

// With mail, nobody goes before the last warning, which gets its full days.
func lapseStep(sub *db.WorkspaceSubscription, mails bool, now time.Time) (lapseAction, int32, time.Time) {
	ends := deletionDate(sub)
	if ends == nil {
		return lapseWait, 0, time.Time{}
	}
	deleteAt, last := *ends, lastWarning(sub)

	left := deleteAt.Sub(now)
	if due := reminderDue(left, sub.DeletionWarning, deletionWarnings(sub)); due != 0 && mails {
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

// deletionDate is nil while the workspace runs and for a manual plan, which the
// operator ends by hand. A late last warning pushes it out.
func deletionDate(sub *db.WorkspaceSubscription) *time.Time {
	ended := entitlement.Ended(sub)
	if ended == nil || (sub.Source != entitlement.SourceTrial && sub.Source != entitlement.SourceStripe) {
		return nil
	}
	ends := deleteAfter(sub.Source, *ended)
	if last := lastWarning(sub); sub.DeletionWarning == last && sub.DeletionWarnedAt != nil {
		ends = later(ends, sub.DeletionWarnedAt.Add(days(last)))
	}
	return &ends
}

// deleteAfter is the date before a late warning moves it.
func deleteAfter(source string, ended time.Time) time.Time {
	if source == entitlement.SourceTrial {
		return entitlement.HoldEnd(ended)
	}
	return ended.Add(days(lapsedKeepDays))
}

func deletionWarnings(sub *db.WorkspaceSubscription) []int32 {
	if sub.Source == entitlement.SourceTrial {
		return trialDeletionWarnings
	}
	return paidDeletionWarnings
}

func lastWarning(sub *db.WorkspaceSubscription) int32 {
	w := deletionWarnings(sub)
	return w[len(w)-1]
}

func warnDeletion(
	ctx context.Context,
	cfg *config.Config,
	row *db.ListLapsedWorkspacesRow,
	due int32,
	deleteAt time.Time,
) {
	sub := &row.WorkspaceSubscription
	err := cfg.Email.SendDeletionWarningEmail(ctx, email.DeletionWarning{
		UserID:     *row.OwnerID,
		Email:      *row.OwnerEmail,
		Workspace:  row.WorkspaceName,
		Slug:       row.Slug,
		BillingURL: billing.Page(cfg.Tenant.BaseURL(row.Slug)),
		Trial:      sub.Source == entitlement.SourceTrial,
		Next:       nextReminder(due, deletionWarnings(sub)),
		Ended:      *entitlement.Ended(sub),
		Deleted:    deleteAt,
	})
	if err != nil && !errors.Is(err, email.ErrCooldown) {
		slog.Warn("deletion warning not sent", "error", err, "workspace_id", sub.WorkspaceID)
		return
	}
	if err := cfg.Conn.Sys().SetDeletionWarning(ctx, &db.SetDeletionWarningParams{
		Days:        due,
		WorkspaceID: sub.WorkspaceID,
	}); err != nil {
		slog.Warn("deletion warning not recorded", "error", err, "workspace_id", sub.WorkspaceID)
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
