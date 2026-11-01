package db

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Both defaults are fine on a laptop and neither is in production.
func TestSettingsWarnsAboutUnsafeDefaults(t *testing.T) {
	var logged bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	t.Setenv("PGPASSWORD", "")
	t.Setenv("PGSSLMODE", "")
	_, _, err := settings()
	require.NoError(t, err)
	assert.Contains(t, logged.String(), "PGPASSWORD is not set")
	assert.Contains(t, logged.String(), "PGSSLMODE is not set")

	logged.Reset()
	t.Setenv("PGPASSWORD", "chosen")
	t.Setenv("PGSSLMODE", "verify-full")
	_, _, err = settings()
	require.NoError(t, err)
	assert.Empty(t, logged.String(), "a configured database got a warning")
}
