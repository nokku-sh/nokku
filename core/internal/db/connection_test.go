package db

import (
	"bytes"
	"log/slog"
	"os"
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

// The defaults go into the pool config, never into the process environment.
func TestSettingsLeavesTheEnvironmentAlone(t *testing.T) {
	keys := []string{"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGSSLMODE"}
	for _, key := range keys {
		t.Setenv(key, "")
	}
	t.Setenv("PGUSER", "chosen")

	_, config, err := settings()
	require.NoError(t, err)
	assert.Equal(t, "localhost", config.ConnConfig.Host)
	assert.EqualValues(t, 5432, config.ConnConfig.Port)
	assert.Equal(t, "nokku", config.ConnConfig.Database)
	assert.Equal(t, "chosen", config.ConnConfig.User, "a set variable lost to its default")
	assert.Equal(t, "postgres", config.ConnConfig.Password)
	assert.Nil(t, config.ConnConfig.TLSConfig)
	for _, key := range keys {
		if key != "PGUSER" {
			assert.Empty(t, os.Getenv(key), "%s went into the environment", key)
		}
	}
}
