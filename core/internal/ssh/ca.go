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

// The kinds of ssh_ca_keys.
const (
	keyUser = "user"
	keyHost = "host"
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
	p.PublicKey, p.HostPublicKey = user.public, host.public
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
func CASigner(ctx context.Context, q *db.Queries, keys *kms.Keyset, caID string, certType uint32) (ssh.Signer, error) {
	kind := keyUser
	if certType == ssh.HostCert {
		kind = keyHost
	}
	row, err := q.GetCASigningKey(ctx, &db.GetCASigningKeyParams{CaID: caID, Kind: kind})
	if err != nil {
		return nil, err
	}
	// The ids come from the row, they are what the key was sealed with.
	der, err := keys.Open(caKeyAAD(row.WorkspaceID, row.CaID, kind), row.PrivateKey)
	if err != nil {
		return nil, err
	}
	signer, err := getSigner(der)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA signer: %w", err)
	}
	if MarshalKey(signer.PublicKey()) != row.PublicKey {
		return nil, errors.New("the private key of the CA does not match its public key")
	}
	return signer, nil
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
	for kind, key := range map[string]caKey{keyUser: user, keyHost: host} {
		sealed, err := keys.Seal(caKeyAAD(ca.WorkspaceID, ca.ID, kind), key.private)
		if err != nil {
			return err
		}
		if err := q.PutCAKey(ctx, &db.PutCAKeyParams{CaID: ca.ID, Kind: kind, PrivateKey: sealed}); err != nil {
			return err
		}
	}
	return nil
}

// caKeyAAD includes the kind, so the two keys of a CA cannot trade places.
func caKeyAAD(workspaceID, caID, kind string) crypto.AAD {
	return crypto.AAD{Table: "ssh_ca_keys", Column: "private_key", Workspace: workspaceID, Row: caID + "/" + kind}
}
