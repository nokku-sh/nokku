package webpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testIssuer is an internal CA for testHost that never saw a database.
func testIssuer(t *testing.T) *issuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &issuer{host: testHost, key: key, root: testRoot(t, key, testHost, time.Now())}
}

func testRoot(t *testing.T, key *ecdsa.PrivateKey, host string, now time.Time) *x509.Certificate {
	t.Helper()
	der, err := newRoot(key, host, now)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return root
}

func verify(leaf, root *x509.Certificate, host string) error {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	_, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots})
	return err
}

func TestInternalCertificateIsForTheHost(t *testing.T) {
	ca := testIssuer(t)
	cert, err := ca.certificate(nil)
	require.NoError(t, err)

	require.NoError(t, verify(cert.Leaf, ca.root, testHost))
	require.Error(t, verify(cert.Leaf, ca.root, "other.test"))
}

// A machine that installs the root trusts it for Nokku only. Whoever gets
// hold of the key cannot sign for the bank of the people who did.
func TestInternalRootSignsForNothingElse(t *testing.T) {
	ca := testIssuer(t)
	sign := func(tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl.SerialNumber = big.NewInt(1)
		tmpl.NotBefore = time.Now().Add(-time.Hour)
		tmpl.NotAfter = time.Now().Add(time.Hour)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert, key
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.root)

	other, _ := sign(&x509.Certificate{DNSNames: []string{"bank.example.com"}}, ca.root, ca.key)
	require.ErrorContains(t, verify(other, ca.root, "bank.example.com"), "not permitted")

	address, _ := sign(&x509.Certificate{
		DNSNames:    []string{testHost},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.5")},
	}, ca.root, ca.key)
	require.ErrorContains(t, verify(address, ca.root, testHost), "excluded")

	sub, subKey := sign(&x509.Certificate{
		Subject:               pkix.Name{CommonName: "sub"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, ca.root, ca.key)
	below, _ := sign(&x509.Certificate{DNSNames: []string{testHost}}, sub, subKey)
	between := x509.NewCertPool()
	between.AddCert(sub)
	_, err := below.Verify(x509.VerifyOptions{DNSName: testHost, Roots: roots, Intermediates: between})
	require.ErrorContains(t, err, "too many intermediates", "the root allows no CA below it")

	client, _ := sign(&x509.Certificate{DNSNames: []string{testHost}}, ca.root, ca.key)
	_, err = client.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	require.ErrorContains(t, err, "incompatible key usage", "the root is for server certificates only")
}

func TestInternalCertificateIsIssuedAgainBeforeItEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ca := testIssuer(t)
		first, err := ca.certificate(nil)
		require.NoError(t, err)

		time.Sleep(leafLifetime - leafRenewBefore - time.Hour)
		same, err := ca.certificate(nil)
		require.NoError(t, err)
		assert.Same(t, first, same)

		time.Sleep(2 * time.Hour)
		next, err := ca.certificate(nil)
		require.NoError(t, err)
		assert.NotSame(t, first, next)
		assert.Greater(t, time.Until(next.Leaf.NotAfter), leafRenewBefore)
		require.NoError(t, verify(next.Leaf, ca.root, testHost))
	})
}

func TestRootFits(t *testing.T) {
	ca := testIssuer(t)
	now := time.Now()
	assert.True(t, rootFits(ca.root, testHost, now))
	assert.False(t, rootFits(ca.root, "moved.test", now), "a new host name needs a new root")
	assert.False(t, rootFits(ca.root, testHost, now.Add(rootLifetime-rootRenewBefore+time.Hour)))
}

// The next root has the key of the old one. A client that still holds the old
// root accepts the server all the same, and its pin stays right.
func TestNextRootKeepsOldClientsWorking(t *testing.T) {
	ca := testIssuer(t)
	old := ca.root
	ca.root = testRoot(t, ca.key, testHost, time.Now().Add(time.Minute))
	require.NotEqual(t, old.Raw, ca.root.Raw)

	cert, err := ca.certificate(nil)
	require.NoError(t, err)
	require.NoError(t, verify(cert.Leaf, old, testHost))

	before, after := &Identity{}, &Identity{}
	before.advertise(old)
	after.advertise(ca.root)
	assert.Equal(t, before.Pin(), after.Pin())
}
