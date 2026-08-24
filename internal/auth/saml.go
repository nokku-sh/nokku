package auth

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/mizuchilabs/kagi"
	"github.com/mizuchilabs/kagi/saml"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

// SAMLSPKeyStore persists the deployment's shared SAML SP keypair in the
// database, encrypting the private key at rest. It implements saml.KeypairStore
// so the kagi handler generates the keypair once and reuses it across
// restarts; one keypair serves every workspace because the SP certificate
// identifies Nokku itself to every IdP.
type SAMLSPKeyStore struct {
	conn *db.Connection
}

// NewSAMLSPKeyStore returns a SAMLSPKeyStore backed by conn.
func NewSAMLSPKeyStore(conn *db.Connection) *SAMLSPKeyStore {
	return &SAMLSPKeyStore{conn: conn}
}

// Load returns the stored keypair as PEM, or kagi.ErrNotFound when none has
// been generated yet.
func (s *SAMLSPKeyStore) Load(ctx context.Context) (keyPEM, certPEM []byte, err error) {
	row, err := s.conn.Q.GetSAMLSPKey(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, kagi.ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	return row.PrivateKey.Bytes(), []byte(row.Certificate), nil
}

// Save stores the generated keypair, encrypting the private key at rest, and
// returns the keypair that is now canonical. The INSERT is idempotent on
// first boot: when several instances start at once, only one wins and every
// caller receives the winner's keypair back, so all pods serve the same SP
// certificate.
func (s *SAMLSPKeyStore) Save(ctx context.Context, keyPEM, certPEM []byte) ([]byte, []byte, error) {
	row, err := s.conn.Q.PutSAMLSPKey(ctx, &db.PutSAMLSPKeyParams{
		PrivateKey:  crypto.EncryptedBytes(keyPEM),
		Certificate: string(certPEM),
	})
	if err != nil {
		return nil, nil, err
	}
	return row.PrivateKey.Bytes(), []byte(row.Certificate), nil
}

var _ saml.KeypairStore = (*SAMLSPKeyStore)(nil)
