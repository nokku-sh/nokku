package db

import (
	"bytes"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureLog(t *testing.T) *bytes.Buffer {
	var logged bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logged
}

func TestWarnDefaultsAboutTheDefaultPassword(t *testing.T) {
	logged := captureLog(t)
	t.Setenv("PGSSLMODE", "")

	t.Setenv("PGPASSWORD", "")
	warnDefaults("localhost")
	assert.Contains(t, logged.String(), "PGPASSWORD is not set")

	logged.Reset()
	t.Setenv("PGPASSWORD", "chosen")
	warnDefaults("localhost")
	assert.Empty(t, logged.String(), "a configured database got a warning")
}

// An unset mode only matters when the traffic leaves the machine.
func TestWarnDefaultsAboutUnverifiedRemoteHosts(t *testing.T) {
	logged := captureLog(t)
	t.Setenv("PGPASSWORD", "chosen")

	t.Setenv("PGSSLMODE", "")
	for _, host := range []string{"localhost", "127.0.0.1", "::1", "/var/run/postgresql"} {
		warnDefaults(host)
		assert.Empty(t, logged.String(), "%s is this machine and got a warning", host)
	}
	for _, host := range []string{"db.internal", "10.0.0.5", "postgres"} {
		logged.Reset()
		warnDefaults(host)
		assert.Contains(t, logged.String(), "PGSSLMODE is not set", "%s is another host", host)
	}

	logged.Reset()
	t.Setenv("PGSSLMODE", "disable")
	warnDefaults("db.internal")
	assert.Empty(t, logged.String(), "a mode chosen on purpose got a warning")
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
	for _, key := range keys {
		if key != "PGUSER" {
			assert.Empty(t, os.Getenv(key), "%s went into the environment", key)
		}
	}
}

// Unset means prefer: TLS first, plain when the server has none.
func TestSettingsPrefersTLSWithoutAMode(t *testing.T) {
	t.Setenv("PGSSLMODE", "")
	_, config, err := settings()
	require.NoError(t, err)
	assert.NotNil(t, config.ConnConfig.TLSConfig, "an unset PGSSLMODE turned TLS off")
	require.Len(t, config.ConnConfig.Fallbacks, 1)
	assert.Nil(t, config.ConnConfig.Fallbacks[0].TLSConfig, "a server without TLS has no plain fallback")

	t.Setenv("PGSSLMODE", "disable")
	_, config, err = settings()
	require.NoError(t, err)
	assert.Nil(t, config.ConnConfig.TLSConfig, "disable still tried TLS")
}
