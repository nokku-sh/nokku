package webpki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/db"
)

const (
	rootLifetime = 10 * 365 * 24 * time.Hour
	// A root this close to its end is issued again with the same key.
	// Clients that pin from then on get the new one, and the pin stays.
	rootRenewBefore = 2 * 365 * 24 * time.Hour
	leafLifetime    = 30 * 24 * time.Hour
	leafRenewBefore = 10 * 24 * time.Hour
	// backdate keeps a client with a slow clock from refusing a fresh certificate.
	backdate = time.Hour
)

// issuer is the CA of NOKKU_TLS=internal. Its key is stored encrypted and
// stays for good, the pin is over that key. What it signs lives in memory
// only, a restart makes a new certificate.
type issuer struct {
	host string
	root *x509.Certificate
	key  *ecdsa.PrivateKey

	mu   sync.Mutex
	leaf *tls.Certificate
}

// loadIssuer reads the CA, makes it on the first start, and gives it a new
// root certificate when the one it has no longer serves host.
func loadIssuer(ctx context.Context, conn *db.Connection, host string) (*issuer, error) {
	ca := &issuer{host: host}
	err := conn.SysTx(ctx, func(q *db.Queries) error {
		row, err := q.LockWebCA(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			row, err = createCA(ctx, q, host)
		}
		if err != nil {
			return err
		}
		key, err := x509.ParsePKCS8PrivateKey(row.PrivateKey)
		if err != nil {
			return err
		}
		var ok bool
		if ca.key, ok = key.(*ecdsa.PrivateKey); !ok {
			return errors.New("the stored CA key is not an ECDSA key")
		}
		if ca.root, err = x509.ParseCertificate(row.Certificate); err != nil {
			return err
		}
		if rootFits(ca.root, host, time.Now()) {
			return nil
		}
		der, err := newRoot(ca.key, host, time.Now())
		if err != nil {
			return err
		}
		if ca.root, err = x509.ParseCertificate(der); err != nil {
			return err
		}
		return q.UpdateWebCACertificate(ctx, der)
	})
	if err != nil {
		return nil, err
	}
	if _, err = ca.certificate(nil); err != nil {
		return nil, err
	}
	return ca, nil
}

// createCA stores a new key and root. ON CONFLICT DO NOTHING and the read
// after it make two servers on their first start end up with the same one.
func createCA(ctx context.Context, q *db.Queries, host string) (*db.LockWebCARow, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	root, err := newRoot(key, host, time.Now())
	if err != nil {
		return nil, err
	}
	if err = q.InsertWebCA(ctx, &db.InsertWebCAParams{PrivateKey: keyDER, Certificate: root}); err != nil {
		return nil, err
	}
	return q.LockWebCA(ctx)
}

// rootFits reports whether root may sign for host and is far from its end.
func rootFits(root *x509.Certificate, host string, now time.Time) bool {
	return slices.Contains(root.PermittedDNSDomains, host) && root.NotAfter.Sub(now) > rootRenewBefore
}

// newRoot returns a self-signed root for key in DER. It can sign server
// certificates for host and the names below it and nothing else, so a
// machine that installs it trusts it for Nokku only.
func newRoot(key *ecdsa.PrivateKey, host string, now time.Time) ([]byte, error) {
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{Organization: []string{"Nokku"}, CommonName: "Nokku CA (" + host + ")"},
		NotBefore:                   now.Add(-backdate),
		NotAfter:                    now.Add(rootLifetime),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLenZero:              true,
		KeyUsage:                    x509.KeyUsageCertSign,
		ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{host},
		ExcludedIPRanges: []*net.IPNet{
			{IP: net.IP{0, 0, 0, 0}, Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		},
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
}

// certificate is the GetCertificate of the listener. It issues the next
// certificate when the current one runs out, so there is no job that a
// server asleep at the wrong time could miss.
func (ca *issuer) certificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	now := time.Now()
	if ca.leaf == nil || ca.leaf.Leaf.NotAfter.Sub(now) < leafRenewBefore {
		leaf, err := ca.issue(now)
		if err != nil {
			return nil, err
		}
		ca.leaf = leaf
	}
	return ca.leaf, nil
}

func (ca *issuer) issue(now time.Time) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: ca.host},
		DNSNames:              []string{ca.host},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(leafLifetime),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.root, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}
