package audit

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
)

//go:embed schema.sql
var schemaSQL string

func (s *Service) Migrate(ctx context.Context) error {
	slog.Debug("migrating audit schema")

	if _, err := s.conn.Pool.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("applying audit schema: %w", err)
	}
	return nil
}
