package db

import (
	"errors"
	"os"
	"regexp"
	"slices"
	"testing"
	"uuid"
)

// A rotation drops old keys once it re-encrypted the columns it knows. An
// encrypted column missing from the list would lose its data.
func TestEncryptedColumnsMatchSqlc(t *testing.T) {
	raw, err := os.ReadFile("../../sqlc.yaml")
	if err != nil {
		t.Fatal(err)
	}
	override := regexp.MustCompile(
		`- column: "([a-z_]+\.[a-z_]+)"\s+go_type:\s+import: "[^"]+"\s+type: "EncryptedBytes"`,
	)
	var want []string
	for _, m := range override.FindAllStringSubmatch(string(raw), -1) {
		want = append(want, m[1])
	}
	var got []string
	for _, c := range encryptedColumns {
		got = append(got, c.table+"."+c.column)
	}
	slices.Sort(want)
	slices.Sort(got)
	if len(want) == 0 || !slices.Equal(got, want) {
		t.Fatalf("encryptedColumns = %v, sqlc.yaml encrypts %v", got, want)
	}
}

// errRollback keeps what the test did out of the shared test database.
var errRollback = errors.New("rollback")

func TestReencrypt(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	recording := uuid.NewV7().String()
	provider := uuid.NewV7().String()

	err := c.WithTx(t.Context(), func(q *Queries) error {
		// The seed row takes its workspace from the pin. Reencrypt itself
		// runs across every workspace.
		if _, err := q.db.Exec(t.Context(), `SELECT set_config('nokku.workspace_id', $1, true)`, f.ws); err != nil {
			return err
		}
		if _, err := q.CreateRecording(t.Context(), &CreateRecordingParams{
			ID: recording, DaemonID: f.daemon, Username: "deploy", Key: []byte("key"),
		}); err != nil {
			return err
		}
		// config defaults to an empty value, which is not a ciphertext.
		if _, err := q.db.Exec(t.Context(),
			`INSERT INTO sso_providers (workspace_id, provider_id) VALUES ($1, $2)`,
			f.ws, provider); err != nil {
			return err
		}

		calls := 0
		mark := func(old []byte) ([]byte, error) {
			calls++
			return append([]byte("new:"), old...), nil
		}
		if err := q.Reencrypt(t.Context(), []byte("new:"), mark); err != nil {
			return err
		}
		var key, config []byte
		if err := q.db.QueryRow(t.Context(), `SELECT key FROM recordings WHERE id = $1`, recording).
			Scan(&key); err != nil {
			return err
		}
		if string(key) != "new:enc:key" {
			t.Errorf("recording key = %q, want it converted once", key)
		}
		if err := q.db.QueryRow(t.Context(), `SELECT config FROM sso_providers WHERE provider_id = $1`, provider).
			Scan(&config); err != nil {
			return err
		}
		if len(config) != 0 {
			t.Errorf("empty config was converted to %q", config)
		}

		// Everything carries the new prefix now, a second pass finds nothing.
		calls = 0
		if err := q.Reencrypt(t.Context(), []byte("new:"), mark); err != nil {
			return err
		}
		if calls != 0 {
			t.Errorf("second pass converted %d values again", calls)
		}

		// A convert that keeps the old key must not loop forever.
		keep := func(old []byte) ([]byte, error) { return old, nil }
		if err := q.Reencrypt(t.Context(), []byte("next"), keep); err == nil {
			t.Error("a value that kept its old key was accepted")
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatalf("reencrypt: %v", err)
	}
}
