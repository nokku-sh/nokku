//go:build integration

package db_test

import (
	"testing"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A token is found by its hash alone, so each hash column has a unique index.
func TestEveryTokenHashIsUnique(t *testing.T) {
	c := testConnection(t)
	rows, err := c.sysPool.Query(t.Context(), `
		SELECT
			col.table_name || '.' || col.column_name,
			EXISTS (
				SELECT 1
				FROM pg_index i
				JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
				WHERE i.indrelid = (quote_ident(col.table_schema) || '.' || quote_ident(col.table_name))::regclass
					AND i.indisunique AND i.indnkeyatts = 1 AND a.attname = col.column_name
			)
		FROM information_schema.columns col
		WHERE col.table_schema = 'public' AND col.column_name LIKE '%\_hash'
		ORDER BY 1`)
	require.NoError(t, err)
	unique := map[string]bool{}
	var column string
	var ok bool
	_, err = pgx.ForEachRow(rows, []any{&column, &ok}, func() error {
		unique[column] = ok
		return nil
	})
	require.NoError(t, err)

	assert.Equal(t, map[string]bool{
		"access_tokens.token_hash":         true,
		"device_grants.device_code_hash":   true,
		"device_grants.loopback_code_hash": true,
		"join_tokens.token_hash":           true,
		"one_time_tokens.token_hash":       true,
	}, unique, "a hash column without a unique index of its own")
}

// The second insert of a hash fails, in another workspace too.
func TestADuplicateTokenHashFails(t *testing.T) {
	c := testConnection(t)
	a, b := newStateFixture(t, c), newStateFixture(t, c)
	for table, insert := range map[string]func(hash string, f stateFixture) error{
		"access_tokens": func(hash string, f stateFixture) error {
			_, err := c.sysPool.Exec(t.Context(), `INSERT INTO access_tokens (token_hash, workspace_id, user_id, kind, method)
				VALUES ($1, $2, $3, 'user', 'passkey')`, hash, f.ws, f.owner)
			return err
		},
		"one_time_tokens": func(hash string, f stateFixture) error {
			_, err := c.sysPool.Exec(t.Context(), `INSERT INTO one_time_tokens (token_hash, workspace_id, user_id, purpose,
				expires_at) VALUES ($1, $2, $3, 'login', NOW() + INTERVAL '1 hour')`, hash, f.ws, f.owner)
			return err
		},
		"device_grants": func(hash string, f stateFixture) error {
			_, err := c.sysPool.Exec(t.Context(), `INSERT INTO device_grants (device_code_hash, workspace_id, user_code,
				expires_at) VALUES ($1, $2, 'BCDF-GHJK', NOW() + INTERVAL '1 hour')`, hash, f.ws)
			return err
		},
		"join_tokens": func(hash string, f stateFixture) error {
			_, err := c.sysPool.Exec(t.Context(),
				`INSERT INTO join_tokens (token_hash, workspace_id) VALUES ($1, $2)`, hash, f.ws)
			return err
		},
	} {
		hash := "h-" + uuid.NewV7().String()
		require.NoError(t, insert(hash, a), "%s: the first insert", table)
		err := insert(hash, b)
		assert.Equal(t, "23505", pgCode(err), "%s: a second row took the same hash, err %v", table, err)
	}
}
