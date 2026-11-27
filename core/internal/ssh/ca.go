package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/crypto/kms"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// The sealed columns of ssh_ca_keys.
const (
	userKeyColumn = "user_private_key"
	hostKeyColumn = "host_private_key"
)

// caKey is Ed25519: private in PKCS#8, public in authorized_keys form.
type caKey struct {
	private []byte
	public  string
}

// NewCA is the only place that states a new CA's settings.
func NewCA() *db.CreateCAParams {
	return &db.CreateCAParams{
		// A work day, and how long people keep working while the core is down.
		UserTtl: 16 * time.Hour,
	}
}

// CreateCA seals both private keys into ssh_ca_keys in the caller's tx.
func CreateCA(ctx context.Context, q *db.Queries, keys *kms.Keyset, p *db.CreateCAParams) (*db.SSHCA, error) {
	user, host, err := newKeys()
	if err != nil {
		return nil, err
	}
	p.UserPublicKey, p.HostPublicKey = user.public, host.public
	ca, err := q.CreateCA(ctx, p)
	if err != nil {
		return nil, err
	}
	if err := putKeys(ctx, q, keys, ca, user, host); err != nil {
		return nil, err
	}
	return ca, nil
}

// CASigner is the one way to a CA's key, which must match the row's public key.
func CASigner(ctx context.Context, q *db.Queries, keys *kms.Keyset, certType uint32) (*db.SSHCA, ssh.Signer, error) {
	row, err := q.GetCASigningKeys(ctx)
	if err != nil {
		return nil, nil, err
	}
	ca := &row.SSHCA
	column, sealed, public := userKeyColumn, row.UserPrivateKey, ca.UserPublicKey
	if certType == ssh.HostCert {
		column, sealed, public = hostKeyColumn, row.HostPrivateKey, ca.HostPublicKey
	}
	// The workspace comes from the row, it is what the key was sealed with.
	der, err := keys.Open(caKeyAAD(ca.WorkspaceID, column), sealed)
	if err != nil {
		return nil, nil, err
	}
	signer, err := getSigner(der)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA signer: %w", err)
	}
	if MarshalKey(signer.PublicKey()) != public {
		return nil, nil, errors.New("the private key of the CA does not match its public key")
	}
	return ca, signer, nil
}

func newKeys() (user, host caKey, err error) {
	if user, err = newKey(); err != nil {
		return caKey{}, caKey{}, err
	}
	host, err = newKey()
	return user, host, err
}

func newKey() (caKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return caKey{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return caKey{}, err
	}
	public, err := MarshalPubKey(pub)
	if err != nil {
		return caKey{}, err
	}
	return caKey{private: der, public: public}, nil
}

func putKeys(ctx context.Context, q *db.Queries, keys *kms.Keyset, ca *db.SSHCA, user, host caKey) error {
	sealedUser, err := keys.Seal(caKeyAAD(ca.WorkspaceID, userKeyColumn), user.private)
	if err != nil {
		return err
	}
	sealedHost, err := keys.Seal(caKeyAAD(ca.WorkspaceID, hostKeyColumn), host.private)
	if err != nil {
		return err
	}
	return q.PutCAKeys(ctx, &db.PutCAKeysParams{UserPrivateKey: sealedUser, HostPrivateKey: sealedHost})
}

// caKeyAAD includes the column, so the two keys of a CA cannot trade places.
func caKeyAAD(workspaceID, column string) crypto.AAD {
	return crypto.AAD{Table: "ssh_ca_keys", Column: column, Workspace: workspaceID, Row: workspaceID}
}
