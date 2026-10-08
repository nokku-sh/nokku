package iam

import (
	"context"
	"log/slog"
	"time"
)

// cleanup hourly deletes expired access tokens, known devices and one-time
// tokens of every workspace.
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
		if _, err := s.conn.Sys().DeleteExpiredTokens(ctx, now); err != nil {
			slog.Error("failed to cleanup one-time tokens", "error", err)
		}
		if _, err := s.conn.Sys().DeleteExpiredAccessTokens(ctx, &now); err != nil {
			slog.Error("failed to cleanup expired access tokens", "error", err)
		}
		if _, err := s.conn.Sys().DeleteExpiredKnownDevices(ctx, now); err != nil {
			slog.Error("failed to cleanup known devices", "error", err)
		}
	}
}
