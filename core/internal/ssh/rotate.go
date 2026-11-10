package ssh

import (
	"context"

	"github.com/nokku-sh/nokku/core/internal/crypto/kms"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// Rollover replaces both keys in the caller's tx. Nothing trusts the old ones.
func Rollover(ctx context.Context, q *db.Queries, keys *kms.Keyset, ca *db.SSHCA) (*db.SSHCA, error) {
	user, host, err := newKeys()
	if err != nil {
		return nil, err
	}
	next, err := q.ReplaceCA(ctx, &db.ReplaceCAParams{
		CaID:          ca.ID,
		UserPublicKey: user.public,
		HostPublicKey: host.public,
	})
	if err != nil {
		return nil, err
	}
	if err := putKeys(ctx, q, keys, next, user, host); err != nil {
		return nil, err
	}
	return next, nil
}
