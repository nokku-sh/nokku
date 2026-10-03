package db

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// encryptedColumns is every column that holds ciphertext of the keyset. A
// key rotation re-encrypts them all and then drops the old keys, so a column
// missing here loses its data. TestEncryptedColumnsMatchSqlc checks the list
// against sqlc.yaml.
var encryptedColumns = []struct{ table, column string }{
	{"certificate_authorities", "private_key"},
	{"sso_providers", "config"},
	{"saml_keypair", "key_enc"},
	{"recordings", "key"},
}

const reencryptBatch = 1000

// Reencrypt passes every stored ciphertext that does not start with prefix
// through convert and writes the result back. It runs in the caller's
// transaction, so a failure changes nothing.
func (q *Queries) Reencrypt(ctx context.Context, prefix []byte, convert func([]byte) ([]byte, error)) error {
	for _, c := range encryptedColumns {
		for {
			// ctid is stable here, the rows are locked until the update.
			rows, err := q.db.Query(ctx, fmt.Sprintf(
				`SELECT ctid, %[2]s FROM %[1]s
				WHERE length(%[2]s) > 0 AND substring(%[2]s FROM 1 FOR $2) <> $1
				LIMIT %[3]d FOR UPDATE`,
				c.table, c.column, reencryptBatch,
			), prefix, len(prefix))
			if err != nil {
				return fmt.Errorf("reading %s.%s: %w", c.table, c.column, err)
			}
			var ids []pgtype.TID
			var values [][]byte
			var id pgtype.TID
			var value []byte
			if _, err := pgx.ForEachRow(rows, []any{&id, &value}, func() error {
				converted, err := convert(value)
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
