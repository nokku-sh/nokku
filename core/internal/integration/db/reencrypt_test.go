//go:build integration

package db_test

import (
	"errors"
	"testing"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"

	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// errRollback keeps what the test did out of the shared test database.
var errRollback = errors.New("rollback")

// Each value is converted once, with the associated data of its row, the same the code that sealed it built.
func TestReencrypt(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	recording := uuid.NewV7().String()
	provider := uuid.NewV7().String()

	err := pgx.BeginFunc(t.Context(), c.sysPool, func(tx pgx.Tx) error {
		q := db.New(tx)
		// The seed rows take their workspace from the pin. Reencrypt itself runs across every workspace.
		if _, err := tx.Exec(t.Context(), `SELECT set_config('nokku.workspace_id', $1, true)`, f.ws); err != nil {
			return err
		}
		if _, err := q.CreateRecording(t.Context(), &db.CreateRecordingParams{
			ID: recording, DaemonID: f.daemon, Username: "deploy", Key: []byte("key"),
		}); err != nil {
			return err
		}
		ca, err := q.CreateCA(t.Context(), &db.CreateCAParams{Name: "ca", PublicKey: "pub", HostPublicKey: "host-pub"})
		if err != nil {
			return err
		}
		if err := q.PutCAKey(t.Context(), &db.PutCAKeyParams{
			CaID: ca.ID, Kind: "host", PrivateKey: []byte("host-key"),
		}); err != nil {
			return err
		}
		// An empty value is no ciphertext, there is nothing to convert.
		if _, err := tx.Exec(t.Context(),
			`INSERT INTO sso_providers (workspace_id, provider_id, config) VALUES ($1, $2, '')`,
			f.ws, provider); err != nil {
			return err
		}

		var seen []crypto.AAD
		mark := func(aad crypto.AAD, old []byte) ([]byte, error) {
			if aad.Workspace == f.ws {
				seen = append(seen, aad)
			}
			return append([]byte("new:"), old...), nil
		}
		if err := q.Reencrypt(t.Context(), []byte("new:"), mark); err != nil {
			return err
		}
		assert.ElementsMatch(t, []crypto.AAD{
			{Table: "ssh_ca_keys", Column: "private_key", Workspace: f.ws, Row: ca.ID + "/host"},
			{Table: "recordings", Column: "key", Workspace: f.ws, Row: recording},
		}, seen, "the values of this workspace, each with its row")

		var key, config []byte
		if err := tx.QueryRow(t.Context(), `SELECT key FROM recordings WHERE id = $1`, recording).
			Scan(&key); err != nil {
			return err
		}
		assert.Equal(t, "new:key", string(key), "the recording key is not converted once")
		if err := tx.QueryRow(t.Context(), `SELECT config FROM sso_providers WHERE provider_id = $1`, provider).
			Scan(&config); err != nil {
			return err
		}
		assert.Empty(t, config, "an empty config was converted")

		// Everything carries the new prefix now, a second pass finds nothing.
		seen = nil
		if err := q.Reencrypt(t.Context(), []byte("new:"), mark); err != nil {
			return err
		}
		assert.Empty(t, seen, "a second pass converted values again")

		// A convert that keeps the old key must not loop forever.
		keep := func(_ crypto.AAD, old []byte) ([]byte, error) { return old, nil }
		assert.Error(t, q.Reencrypt(t.Context(), []byte("next"), keep), "a value that kept its old key was accepted")
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatalf("reencrypt: %v", err)
	}
}
