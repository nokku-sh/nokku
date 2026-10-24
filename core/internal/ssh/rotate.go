package ssh

import (
	"context"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// Rollover replaces both keys. The replaced ones stay trusted until their certificates expire, unless
// revokePrevious drops them at once, for a key that leaked.
func Rollover(ctx context.Context, q *db.Queries, ca *db.SSHCA, revokePrevious bool) (*db.SSHCA, error) {
	keys, err := NewCA()
	if err != nil {
		return nil, err
	}
	return q.ReplaceCA(ctx, &db.ReplaceCAParams{
		CaID:           ca.ID,
		PrivateKey:     keys.PrivateKey,
		PublicKey:      keys.PublicKey,
		HostPrivateKey: keys.HostPrivateKey,
		HostPublicKey:  keys.HostPublicKey,
		RevokePrevious: revokePrevious,
	})
}
