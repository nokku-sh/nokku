package hostcerts

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

type testCA struct {
	pub    ssh.PublicKey
	signer ssh.Signer
}

func newTestCA(t testing.TB) testCA {
	t.Helper()
	must := require.New(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	must.NoError(err, "generate CA key")
	signer, err := ssh.NewSignerFromKey(priv)
	must.NoError(err, "CA signer")
	pub, err := ssh.NewPublicKey(priv.Public())
	must.NoError(err, "CA public key")
	return testCA{pub: pub, signer: signer}
}

func signHostCert(
	t testing.TB,
	ca testCA,
	hostPub ssh.PublicKey,
	principal string,
	validAfter, validBefore uint64,
) []byte {
	t.Helper()
	must := require.New(t)
	cert := &ssh.Certificate{
		Key:             hostPub,
		CertType:        ssh.HostCert,
		KeyId:           "test-host",
		ValidPrincipals: []string{principal},
		ValidAfter:      validAfter,
		ValidBefore:     validBefore,
	}
	must.NoError(cert.SignCert(rand.Reader, ca.signer), "sign cert")
	return ssh.MarshalAuthorizedKey(cert)
}

func newHostPub(t testing.TB) ssh.PublicKey {
	t.Helper()
	must := require.New(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must.NoError(err, "generate host key")
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	must.NoError(err, "host public key")
	return pub
}

func writeHostKey(t testing.TB, dir string) ssh.PublicKey {
	t.Helper()
	must := require.New(t)
	pub := newHostPub(t)
	must.NoError(os.WriteFile(
		filepath.Join(dir, "ssh_host_ecdsa_key.pub"),
		ssh.MarshalAuthorizedKey(pub),
		0o644,
	), "write host pub")
	return pub
}

func TestNeedsRenewal(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		setup    func(t *testing.T, dir string, ca testCA)
		targetID string
		want     bool
	}{
		{
			name: "missing certificate is outdated",
			setup: func(t *testing.T, dir string, _ testCA) {
				writeHostKey(t, dir)
			},
			targetID: "target-1",
			want:     true,
		},
		{
			name: "certificate for another principal is outdated",
			setup: func(t *testing.T, dir string, ca testCA) {
				hostPub := writeHostKey(t, dir)
				certText := signHostCert(t, ca, hostPub, "other-target", 0, ssh.CertTimeInfinity)
				writeCert(t, dir, certText)
			},
			targetID: "target-1",
			want:     true,
		},
		{
			name: "expiring certificate is outdated",
			setup: func(t *testing.T, dir string, ca testCA) {
				hostPub := writeHostKey(t, dir)
				certText := signHostCert(
					t, ca, hostPub, "target-1", 0, uint64(now.Add(24*time.Hour).Unix()),
				)
				writeCert(t, dir, certText)
			},
			targetID: "target-1",
			want:     true,
		},
		{
			name: "expired certificate is outdated",
			setup: func(t *testing.T, dir string, ca testCA) {
				hostPub := writeHostKey(t, dir)
				certText := signHostCert(
					t,
					ca,
					hostPub,
					"target-1",
					0,
					uint64(now.Add(-time.Hour).Unix()),
				)
				writeCert(t, dir, certText)
			},
			targetID: "target-1",
			want:     true,
		},
		{
			name: "valid certificate is not outdated",
			setup: func(t *testing.T, dir string, ca testCA) {
				hostPub := writeHostKey(t, dir)
				certText := signHostCert(
					t, ca, hostPub, "target-1", uint64(now.Add(-time.Hour).Unix()),
					uint64(now.Add(90*24*time.Hour).Unix()),
				)
				writeCert(t, dir, certText)
			},
			targetID: "target-1",
			want:     false,
		},
		{
			name: "certificate from another CA is outdated",
			setup: func(t *testing.T, dir string, _ testCA) {
				hostPub := writeHostKey(t, dir)
				certText := signHostCert(
					t, newTestCA(t), hostPub, "target-1", uint64(now.Add(-time.Hour).Unix()),
					uint64(now.Add(90*24*time.Hour).Unix()),
				)
				writeCert(t, dir, certText)
			},
			targetID: "target-1",
			want:     true,
		},
		{
			name:     "no keys means nothing to renew",
			setup:    func(_ *testing.T, _ string, _ testCA) {},
			targetID: "target-1",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := assert.New(t)
			dir := t.TempDir()
			ca := newTestCA(t)
			tt.setup(t, dir, ca)

			t.Setenv("NOKKUD_DATA_DIR", dir)
			_, got := needsRenewal(tt.targetID, ca.pub)
			is.Equal(tt.want, got)
		})
	}
}

func TestNextRenewal(t *testing.T) {
	now := time.Now()
	ca := newTestCA(t)
	caKey := string(ssh.MarshalAuthorizedKey(ca.pub))

	t.Run("no certificates schedules immediately", func(t *testing.T) {
		is := assert.New(t)
		dir := t.TempDir()
		t.Setenv("NOKKUD_DATA_DIR", dir)
		got := NextRenewal("target-1", caKey)
		is.False(got.IsZero(), "NextRenewal returned zero time with no certificates")
		is.False(got.After(now.Add(time.Minute)), "NextRenewal = %v, want ~now", got)
	})

	t.Run("a certificate renews at half of its life", func(t *testing.T) {
		is := assert.New(t)
		dir := t.TempDir()
		hostPub := writeHostKey(t, dir)

		// The default host TTL, issued a minute ago.
		after := uint64(now.Add(-time.Minute).Unix())
		before := uint64(now.Add(7 * 24 * time.Hour).Unix())
		certText := signHostCert(t, ca, hostPub, "target-1", after, before)
		writeCert(t, dir, certText)

		t.Setenv("NOKKUD_DATA_DIR", dir)
		got := NextRenewal("target-1", caKey)

		want := now.Add(84 * time.Hour)
		is.InDelta(
			float64(want.UnixNano()), float64(got.UnixNano()), float64(2*time.Minute),
			"NextRenewal = %v, want ~%v", got, want,
		)
	})

	t.Run("a certificate that never expires is not polled", func(t *testing.T) {
		is := assert.New(t)
		dir := t.TempDir()
		hostPub := writeHostKey(t, dir)
		certText := signHostCert(t, ca, hostPub, "target-1", 0, ssh.CertTimeInfinity)
		writeCert(t, dir, certText)

		t.Setenv("NOKKUD_DATA_DIR", dir)
		got := NextRenewal("target-1", caKey)
		is.True(got.After(now.Add(time.Hour)), "NextRenewal with a never expiring cert = %v, want far ahead", got)
	})

	t.Run("outdated certificate schedules immediately", func(t *testing.T) {
		is := assert.New(t)
		dir := t.TempDir()
		hostPub := writeHostKey(t, dir)
		certText := signHostCert(t, ca, hostPub, "wrong-target", 0, ssh.CertTimeInfinity)
		writeCert(t, dir, certText)

		t.Setenv("NOKKUD_DATA_DIR", dir)
		got := NextRenewal("target-1", caKey)
		is.False(got.After(now.Add(time.Minute)), "NextRenewal with outdated cert = %v, want ~now", got)
	})

	t.Run("a certificate from a replaced CA schedules immediately", func(t *testing.T) {
		is := assert.New(t)
		dir := t.TempDir()
		hostPub := writeHostKey(t, dir)
		certText := signHostCert(
			t, newTestCA(t), hostPub, "target-1",
			uint64(now.Add(-time.Minute).Unix()), uint64(now.Add(7*24*time.Hour).Unix()),
		)
		writeCert(t, dir, certText)

		t.Setenv("NOKKUD_DATA_DIR", dir)
		got := NextRenewal("target-1", caKey)
		is.False(got.After(now.Add(time.Minute)), "NextRenewal after a CA change = %v, want ~now", got)
	})
}

func TestRenewHostCertsSignFailure(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	dir := t.TempDir()
	writeHostKey(t, dir)

	t.Setenv("NOKKUD_DATA_DIR", dir)

	calls := 0
	sign := func(_ context.Context, _ []byte) (string, error) {
		calls++
		return "", errors.New("core refused")
	}

	caKey := string(ssh.MarshalAuthorizedKey(newTestCA(t).pub))
	renewed, err := RenewHostCerts(context.Background(), "target-1", caKey, sign)
	must.Error(err, "expected the sign error to be returned")
	is.False(renewed)
	is.Equal(1, calls)

	_, statErr := os.Stat(paths.HostKeyCert())
	must.ErrorIs(statErr, os.ErrNotExist, "failed renewal must not write a certificate")
}

func TestRenewHostCertsWithoutCA(t *testing.T) {
	dir := t.TempDir()
	writeHostKey(t, dir)
	t.Setenv("NOKKUD_DATA_DIR", dir)

	sign := func(context.Context, []byte) (string, error) {
		t.Fatal("signed a host certificate without a trusted CA")
		return "", nil
	}
	renewed, err := RenewHostCerts(context.Background(), "target-1", "", sign)
	require.NoError(t, err)
	assert.False(t, renewed)
}

func TestRenewHostCertsFollowsCA(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	dir := t.TempDir()
	old, next := newTestCA(t), newTestCA(t)
	hostPub := writeHostKey(t, dir)

	now := time.Now()
	certText := signHostCert(
		t, old, hostPub, "target-1",
		uint64(now.Add(-time.Hour).Unix()),
		uint64(now.Add(90*24*time.Hour).Unix()),
	)
	writeCert(t, dir, certText)

	t.Setenv("NOKKUD_DATA_DIR", dir)

	signer := old
	sign := func(_ context.Context, _ []byte) (string, error) {
		cert := signHostCert(t, signer, hostPub, "target-1", 0, ssh.CertTimeInfinity)
		return string(cert), nil
	}
	oldKey, nextKey := string(ssh.MarshalAuthorizedKey(old.pub)), string(ssh.MarshalAuthorizedKey(next.pub))

	renewed, err := RenewHostCerts(context.Background(), "target-1", oldKey, sign)
	must.NoError(err, "renew under the same CA")
	is.False(renewed, "a valid certificate was rewritten")

	// The core still signs with the old key, so the certificate is refused and the one on disk stays.
	renewed, err = RenewHostCerts(context.Background(), "target-1", nextKey, sign)
	must.Error(err, "a certificate from another CA than the trusted one was stored")
	is.False(renewed)

	signer = next
	renewed, err = RenewHostCerts(context.Background(), "target-1", nextKey, sign)
	must.NoError(err, "renew after the rollover")
	is.True(renewed, "the certificate of the replaced CA was kept")
	cert, err := Load()
	must.NoError(err)
	is.True(signedBy(cert, next.pub))
}

func writeCert(t testing.TB, dir string, data []byte) {
	t.Helper()
	must := require.New(t)
	must.NoError(os.WriteFile(
		filepath.Join(dir, "ssh_host_ecdsa_key-cert.pub"),
		data,
		0o644,
	), "write certificate")
}
