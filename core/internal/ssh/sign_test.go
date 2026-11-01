package ssh

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestSignCertificate_UnspecifiedTypeIsUser(t *testing.T) {
	ca := newTestCA(t)

	cert, err := SignCertificate(ca.row, ca.user, newTestKey(t), []string{"alice"}, "k", time.Hour, 0, Limits{})
	require.NoError(t, err)
	assert.EqualValues(t, ssh.UserCert, cert.CertType)
}

func TestSignCertificate_Errors(t *testing.T) {
	ca := newTestCA(t)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)
	rsaPub, err := MarshalPubKey(&rsaKey.PublicKey)
	require.NoError(t, err)

	tests := []struct {
		name    string
		pub     string
		wantErr string
	}{
		{"invalid public key", "not-a-key", "public key"},
		{"RSA key", rsaPub, "not accepted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SignCertificate(
				ca.row,
				ca.user,
				tt.pub,
				[]string{"alice"},
				"k",
				time.Hour,
				ssh.UserCert,
				Limits{},
			)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestBoundTTL(t *testing.T) {
	tests := []struct {
		name string
		ttl  time.Duration
		want time.Duration
	}{
		{"zero", 0, time.Hour},
		{"negative", -time.Minute, time.Hour},
		{"over max", 48 * time.Hour, time.Hour},
		{"in range", 30 * time.Minute, 30 * time.Minute},
		{"exactly max", 24 * time.Hour, 24 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, boundTTL(tt.ttl, time.Hour, 24*time.Hour))
		})
	}
}

func TestAcceptedKey(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)
	for name, tc := range map[string]struct {
		key    any
		accept bool
	}{
		"ed25519": {ed.Public(), true},
		"p-256":   {&ec.PublicKey, true},
		"rsa":     {&rsaKey.PublicKey, false},
	} {
		pub, err := ssh.NewPublicKey(tc.key)
		require.NoError(t, err)
		assert.Equal(t, tc.accept, acceptedKey(pub) == nil, "acceptedKey(%s)", name)
	}
}

// A forced command is all a login may do. Others keep what the host allows.
func TestUserPermissions_ForcedCommandEndsForwarding(t *testing.T) {
	forced := userPermissions(Limits{ForceCommand: "/usr/local/bin/backup"}).Extensions
	assert.Equal(t, map[string]string{"permit-pty": ""}, forced, "extensions with a forced command")
	assert.Equal(t, userExtensions, userPermissions(Limits{}).Extensions, "extensions without one")
	assert.Equal(t, map[string]string{
		"permit-pty": "", "permit-user-rc": "", "permit-port-forwarding": "", "permit-agent-forwarding": "",
	}, userExtensions, "a forced command changed the shared map")
}

func TestUserPermissions_Limits(t *testing.T) {
	assert.Empty(t, userPermissions(Limits{}).CriticalOptions, "no limits wrote options")

	limits := Limits{ForceCommand: "/usr/local/bin/backup", SourceAddress: "10.0.0.0/8,192.0.2.7"}
	want := map[string]string{"force-command": "/usr/local/bin/backup", "source-address": "10.0.0.0/8,192.0.2.7"}
	assert.Equal(t, want, userPermissions(limits).CriticalOptions)
}

// sshd and nokkud split on commas and trim nothing, so it is stored that way.
func TestSourceAddresses(t *testing.T) {
	for in, want := range map[string]string{
		"":                            "",
		" , ":                         "",
		"10.0.0.0/8, 192.168.1.10":    "10.0.0.0/8,192.168.1.10",
		" 2001:db8::/32 ,2001:db8::1": "2001:db8::/32,2001:db8::1",
	} {
		got, err := SourceAddresses(in)
		if assert.NoError(t, err, "SourceAddresses(%q)", in) {
			assert.Equal(t, want, got, "SourceAddresses(%q)", in)
		}
	}
	for _, in := range []string{"office", "10.0.0.0/33", "10.0.0.1 10.0.0.2"} {
		_, err := SourceAddresses(in)
		assert.Error(t, err, "SourceAddresses(%q) took a list no server can read", in)
	}
}

func TestSignUserCertificate(t *testing.T) {
	ca := newTestCA(t)

	cert, err := SignCertificate(
		ca.row,
		ca.user,
		newTestKey(t),
		[]string{"user-123"},
		"nokku:login:user:alice:user-123",
		0,
		ssh.UserCert,
		Limits{},
	)
	require.NoError(t, err)

	assert.EqualValues(t, ssh.UserCert, cert.CertType)
	assert.Equal(t, []string{"user-123"}, cert.ValidPrincipals)
	// The same set for every CA, a host decides what a session may do.
	assert.Equal(t, userExtensions, cert.Permissions.Extensions)
	// Default user TTL is 24h (plus 1m clock-skew allowance on ValidAfter)
	assert.GreaterOrEqual(t, validity(cert), 24*time.Hour)
	assert.LessOrEqual(t, validity(cert), 24*time.Hour+2*time.Minute)
	require.NoError(t, checkCert(t, ca.row, cert, "user-123"), "certificate failed verification")
}

func TestSignHostCertificate(t *testing.T) {
	ca := newTestCA(t)

	cert, err := SignCertificate(
		ca.row,
		ca.host,
		newTestKey(t),
		[]string{"target-123"},
		"nokku:provision:daemon:d:d",
		0,
		ssh.HostCert,
		Limits{},
	)
	require.NoError(t, err)

	assert.EqualValues(t, ssh.HostCert, cert.CertType)
	assert.Empty(t, cert.Permissions.Extensions, "host certs must not carry user extensions")
	// The host TTL is 2160h (90 days)
	assert.GreaterOrEqual(t, validity(cert), 2160*time.Hour)
	assert.LessOrEqual(t, validity(cert), 2160*time.Hour+2*time.Minute)
	require.NoError(t, checkCert(t, ca.row, cert, "target-123"), "certificate failed verification")
}

func TestSignCertificateTTLBounds(t *testing.T) {
	ca := newTestCA(t)

	cert, err := SignCertificate(ca.row, ca.user, newTestKey(t), []string{"u"}, "k", -time.Hour, 0, Limits{})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, validity(cert), 24*time.Hour, "negative TTL should fall back to default")

	cert, err = SignCertificate(ca.row, ca.user, newTestKey(t), []string{"u"}, "k", 1000*time.Hour, 0, Limits{})
	require.NoError(t, err)
	assert.LessOrEqual(t, validity(cert), 25*time.Hour, "over-max TTL should fall back to default")

	cert, err = SignCertificate(ca.row, ca.user, newTestKey(t), []string{"u"}, "k", 2*time.Hour, 0, Limits{})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, validity(cert), 2*time.Hour)
	assert.LessOrEqual(t, validity(cert), 2*time.Hour+2*time.Minute)
}

// No principals is valid for every account, and OpenSSH reads at most 256.
func TestSignCertificatePrincipalCount(t *testing.T) {
	ca := newTestCA(t)
	for why, principals := range map[string][]string{
		"without principals":                      nil,
		"with more principals than OpenSSH reads": make([]string, maxPrincipals+1),
	} {
		_, err := SignCertificate(ca.row, ca.user, newTestKey(t), principals, "k", 0, ssh.UserCert, Limits{})
		assert.Error(t, err, "signed a certificate %s", why)
	}
}
