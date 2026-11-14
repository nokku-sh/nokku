package api

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"github.com/nokku-sh/nokku/core/internal/app"
	"github.com/nokku-sh/nokku/core/internal/email"
)

// streamFailingWait rides out a destination's bad day before its owner gets a mail.
const streamFailingWait = 24 * time.Hour

// A failing stream keeps its events and says so only in the console, where nobody looks while all seems well.
func runStreamAlerts(ctx context.Context, cfg *app.Config) {
	// Without SMTP a mail goes nowhere, and marking it would skip it for good.
	if !cfg.Email.HasSMTP() {
		return
	}
	tick := time.Tick(time.Hour)
	for {
		warnFailingStreams(ctx, cfg)
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
	}
}

// A stream is marked only once its mail went out, so a mail outage retries it.
func warnFailingStreams(ctx context.Context, cfg *app.Config) {
	rows, err := cfg.Conn.Sys().ListAuditStreamsFailingLong(ctx, streamFailingWait)
	if err != nil {
		slog.Error("listing failing audit streams failed", "error", err)
		return
	}
	for _, row := range rows {
		host := row.URL
		if u, err := url.Parse(row.URL); err == nil {
			host = u.Host
		}
		err := cfg.Email.SendStreamFailingEmail(ctx, email.StreamFailing{
			UserID:    row.OwnerID,
			Email:     row.OwnerEmail,
			Workspace: row.WorkspaceName,
			StreamID:  row.ID,
			Kind:      row.Kind,
			Host:      host,
			LastError: row.LastError,
			URL:       cfg.Tenant.BaseURL(row.Slug) + "/audit",
			Since:     row.FailingSince,
		})
		if err != nil && !errors.Is(err, email.ErrCooldown) {
			slog.Warn("stream failure mail not sent", "error", err, "stream_id", row.ID)
			continue
		}
		if err := cfg.Conn.Sys().SetAuditStreamFailureMailed(ctx, row.ID); err != nil {
			slog.Warn("stream failure mail not recorded", "error", err, "stream_id", row.ID)
		}
	}
}
