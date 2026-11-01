//go:build integration

package db_test

import (
	"testing"
	"uuid"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A row like these is a bug in some writer, and the database is the one place every writer passes through.
func TestInvalidRowsAreRefused(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	id := func() string { return uuid.NewV7().String() }
	subscription := `INSERT INTO workspace_subscriptions (workspace_id, source, plan, status) VALUES ($1, $2, $3, 'active')`
	joinToken := `INSERT INTO join_tokens (workspace_id, token_hash, max_uses, uses, retire_after)
		VALUES ($1, $2, $3, $4, $5::INTERVAL)`
	request := `INSERT INTO access_requests (workspace_id, requester_id, account_id, duration, reason, status)
		VALUES ($1, $2, $3, $4::INTERVAL, 'because', $5)`
	recording := `INSERT INTO recordings (workspace_id, daemon_name, username, key, complete, size_bytes, ended_at)
		VALUES ($1, 'd', 'u', '\x00', $2, $3, NOW() - $4::INTERVAL)`

	for name, stmt := range map[string]struct {
		sql  string
		args []any
	}{
		"a subscription from nowhere": {subscription, []any{f.ws, "gift", "pro"}},
		"a plan that does not exist":  {subscription, []any{f.ws, "stripe", "gold"}},
		"a trial with no end": {
			`INSERT INTO workspace_subscriptions (workspace_id, source, plan, status) VALUES ($1, 'trial', 'pro', 'trial')`,
			[]any{f.ws},
		},
		"half of a previous CA key": {`UPDATE ssh_cas SET previous_public_key = 'old' WHERE id = $1`, []any{f.ca}},
		"a certificate lifetime of nothing": {
			`UPDATE ssh_cas SET user_default_ttl = '0' WHERE id = $1`, []any{f.ca},
		},
		"an owner switched off": {`UPDATE users SET active = FALSE WHERE id = $1`, []any{f.owner}},
		"an identity with no subject": {
			`INSERT INTO credentials (id, workspace_id, user_id, type, provider) VALUES ($1, $2, $3, 'oidc', 'okta')`,
			[]any{id(), f.ws, f.u},
		},
		"an approved nk login with no method": {
			`INSERT INTO device_grants (device_code_hash, workspace_id, user_code, status, user_id, expires_at)
				VALUES ($1, $2, 'CODE', 'approved', $3, NOW())`,
			[]any{id(), f.ws, f.u},
		},
		"a token past its uses":      {joinToken, []any{f.ws, id(), 1, 2, nil}},
		"a token that retires early": {joinToken, []any{f.ws, id(), nil, 0, "-1 minute"}},
		"a request for no time":      {request, []any{f.ws, f.u, f.account, "0", "pending"}},
		"a decision with no time":    {request, []any{f.ws, f.u, f.account, "1 hour", "approved"}},
		"a whole recording with no object": {
			recording, []any{f.ws, true, 0, "-1 hour"},
		},
		"a recording of negative size":           {recording, []any{f.ws, false, -1, "-1 hour"}},
		"a recording that ended before it began": {recording, []any{f.ws, false, 0, "1 hour"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.sysPool.Exec(t.Context(), stmt.sql, stmt.args...)
			var pgErr *pgconn.PgError
			require.ErrorAs(t, err, &pgErr, "the row was stored, err=%v", err)
			assert.Equal(t, pgerrcode.CheckViolation, pgErr.Code, pgErr.Message)
		})
	}
}
