package api

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
)

func TestReminderDue(t *testing.T) {
	day := 24 * time.Hour
	tests := []struct {
		name     string
		schedule []int32
		left     time.Duration
		sent     int32
		want     int32
	}{
		{"too early", trialReminders, 8 * day, 0, 0},
		{"the first reminder", trialReminders, 7 * day, 0, 7},
		{"the first one went out", trialReminders, 5 * day, 7, 0},
		{"the second reminder", trialReminders, 3 * day, 7, 3},
		{"both went out", trialReminders, day, 3, 0},
		{"a late run sends only the last one", trialReminders, 2 * day, 0, 3},
		{"a month before a paid workspace goes", paidDeletionWarnings, 30 * day, 0, 30},
		{"a week before", paidDeletionWarnings, 6 * day, 30, 7},
		{"past the date the last warning is still owed", paidDeletionWarnings, -day, 30, 7},
		{"past the date after the last warning", paidDeletionWarnings, -day, 7, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, reminderDue(tt.left, tt.sent, tt.schedule))
		})
	}
}

func TestNextReminder(t *testing.T) {
	assert.EqualValues(t, 3, nextReminder(7, trialReminders))
	assert.Zero(t, nextReminder(3, trialReminders), "the last reminder promises no other")
	assert.EqualValues(t, 7, nextReminder(30, paidDeletionWarnings))
	assert.Zero(t, nextReminder(7, trialDeletionWarnings))
}

func TestLapseStep(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour
	// A paid plan that ended this long ago is deleted 180 days after it ended.
	paid := func(endedAgo time.Duration, warned int32, warnedAgo time.Duration) *db.WorkspaceSubscription {
		sub := &db.WorkspaceSubscription{
			Source: "stripe", Status: "canceled", EndedAt: new(now.Add(-endedAgo)), DeletionWarning: warned,
		}
		if warned != 0 {
			sub.DeletionWarnedAt = new(now.Add(-warnedAgo))
		}
		return sub
	}
	tests := []struct {
		name       string
		sub        *db.WorkspaceSubscription
		mails      bool
		want       lapseAction
		wantDue    int32
		wantDelete time.Time
	}{
		{
			"a running plan",
			&db.WorkspaceSubscription{Source: "stripe", Status: "active"},
			true,
			lapseWait,
			0,
			time.Time{},
		},
		{"months to go", paid(30*day, 0, 0), true, lapseWait, 0, now.Add(150 * day)},
		{"the first warning", paid(151*day, 0, 0), true, lapseWarn, 30, now.Add(29 * day)},
		{"the last warning", paid(173*day, 30, 23*day), true, lapseWarn, 7, now.Add(7 * day)},
		{"a day late it still gives a week", paid(174*day, 30, 23*day), true, lapseWarn, 7, now.Add(7 * day)},
		{"warned, the date has not come", paid(176*day, 7, 2*day), true, lapseWait, 0, now.Add(5 * day)},
		{"warned and due", paid(181*day, 7, 8*day), true, lapseDelete, 0, now.Add(-1 * day)},
		{
			// The mail server was down until the date passed.
			"a late last warning gives a full week",
			paid(200*day, 30, 40*day), true, lapseWarn, 7, now.Add(7 * day),
		},
		{"a late warning holds the deletion", paid(200*day, 7, 2*day), true, lapseWait, 0, now.Add(5 * day)},
		{"no mail to send deletes on the date", paid(181*day, 0, 0), false, lapseDelete, 0, now.Add(-1 * day)},
		{"no mail to send waits for the date", paid(170*day, 0, 0), false, lapseWait, 0, now.Add(10 * day)},
		{
			"a trial gets one warning",
			&db.WorkspaceSubscription{Source: entitlement.SourceTrial, CurrentPeriodEnd: new(now.Add(-25 * day))},
			true, lapseWarn, 7, now.Add(7 * day),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, due, deleteAt := lapseStep(tt.sub, tt.mails, now)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantDue, due)
			assert.WithinDuration(t, tt.wantDelete, deleteAt, time.Minute)
		})
	}
}

func TestDeletionDate(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour
	trialEnd, paidEnd := now.Add(-time.Hour), now.Add(-10*day)
	tests := []struct {
		name string
		sub  *db.WorkspaceSubscription
		want *time.Time
	}{
		{
			"a running trial",
			&db.WorkspaceSubscription{Source: entitlement.SourceTrial, CurrentPeriodEnd: new(now.Add(day))},
			nil,
		},
		{
			"an ended trial waits out the hold",
			&db.WorkspaceSubscription{Source: entitlement.SourceTrial, CurrentPeriodEnd: &trialEnd},
			new(entitlement.HoldEnd(trialEnd)),
		},
		{"a paid plan", &db.WorkspaceSubscription{Source: "stripe", Status: "active"}, nil},
		{
			"a lapsed paid plan waits half a year",
			&db.WorkspaceSubscription{Source: "stripe", Status: "canceled", EndedAt: &paidEnd},
			new(paidEnd.Add(180 * day)),
		},
		{
			"an abandoned checkout never ended",
			&db.WorkspaceSubscription{Source: "stripe", Status: "incomplete_expired"},
			nil,
		},
		{"a manual plan", &db.WorkspaceSubscription{Source: "manual", Status: "canceled", EndedAt: &paidEnd}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deletionDate(tt.sub)
			if tt.want == nil {
				assert.Nil(t, got)
				return
			}
			if assert.NotNil(t, got) {
				assert.WithinDuration(t, *tt.want, *got, time.Second)
			}
		})
	}
}
