package iam

import (
	"context"
	"log/slog"
	"time"
)

const unverifiedUserTTL = 48 * time.Hour

// cleanup hourly deletes expired sessions and one-time tokens, and accounts
// never verified within unverifiedUserTTL.
func (s *Service) cleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		now := s.now()
		if _, err := s.sys.DeleteUnverifiedUsers(ctx, now.Add(-unverifiedUserTTL)); err != nil {
			slog.Error("failed to cleanup unverified users", "error", err)
		}
		if _, err := s.sys.DeleteExpiredTokens(ctx, now); err != nil {
			slog.Error("failed to cleanup one-time tokens", "error", err)
		}
		if _, err := s.sys.DeleteExpiredSessions(ctx, &now); err != nil {
			slog.Error("failed to cleanup expired sessions", "error", err)
		}
	}
}
