package db

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/nokku-sh/nokku/core/internal/crypto"
)

// sealedColumns is every column holding a crypto.Sealed. One missing here loses its data on a rotation. row is the
// SQL for crypto.AAD.Row, it must give the same string as the code that seals the column.
var sealedColumns = []struct{ table, column, row string }{
	{"ssh_ca_keys", "private_key", "ca_id::TEXT || '/' || kind"},
	{"sso_providers", "config", "provider_id"},
	{"recordings", "key", "id::TEXT"},
	{"audit_streams", "secret", "id::TEXT"},
}

const reencryptBatch = 1000

// Reencrypt converts every ciphertext that does not start with prefix, in the caller's transaction. convert gets the
// associated data the column was sealed with.
func (q *Queries) Reencrypt(
	ctx context.Context,
	prefix []byte,
	convert func(aad crypto.AAD, ciphertext []byte) ([]byte, error),
) error {
	for _, c := range sealedColumns {
		for {
			// ctid is stable here, the rows are locked until the update.
			rows, err := q.db.Query(ctx, fmt.Sprintf(
				`SELECT ctid, workspace_id::TEXT, %[3]s, %[2]s FROM %[1]s
				WHERE length(%[2]s) > 0 AND substring(%[2]s FROM 1 FOR $2) <> $1
				LIMIT %[4]d FOR UPDATE`,
				c.table, c.column, c.row, reencryptBatch,
			), prefix, len(prefix))
			if err != nil {
				return fmt.Errorf("reading %s.%s: %w", c.table, c.column, err)
			}
			var ids []pgtype.TID
			var values [][]byte
			var id pgtype.TID
			var workspace, row string
			var value []byte
			if _, err := pgx.ForEachRow(rows, []any{&id, &workspace, &row, &value}, func() error {
				aad := crypto.AAD{Table: c.table, Column: c.column, Workspace: workspace, Row: row}
				converted, err := convert(aad, value)
				if err != nil {
					return err
				}
				if !bytes.HasPrefix(converted, prefix) {
					return errors.New("converted value does not use the new key")
				}
				ids = append(ids, id)
				values = append(values, converted)
				return nil
			}); err != nil {
				return fmt.Errorf("re-encrypting %s.%s: %w", c.table, c.column, err)
			}
			if len(ids) == 0 {
				break
			}
			if _, err := q.db.Exec(ctx, fmt.Sprintf(
				`UPDATE %[1]s AS t SET %[2]s = d.value
				FROM unnest($1::tid[], $2::bytea[]) AS d (id, value)
				WHERE t.ctid = d.id`,
				c.table, c.column,
			), ids, values); err != nil {
				return fmt.Errorf("writing %s.%s: %w", c.table, c.column, err)
			}
		}
	}
	return nil
}
