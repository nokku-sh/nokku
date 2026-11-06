package ssh

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"maps"
	"math"
	"net"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// maxPrincipals is how many principals OpenSSH reads from one certificate.
const maxPrincipals = 256

// What a session may really do is the host's call: the daemon config where
// nokkud runs, sshd_config where it does not.
var userExtensions = map[string]string{
	"permit-pty":              "",
	"permit-user-rc":          "",
	"permit-port-forwarding":  "",
	"permit-agent-forwarding": "",
}

// RefusedError has a reason for the caller, any other error is the server's.
type RefusedError struct{ Reason string }

// Limits are a login certificate's critical options.
type Limits struct {
	ForceCommand  string
	SourceAddress string
}

func (e *RefusedError) Error() string { return e.Reason }

// SignCertificate refuses an empty principal list, such a certificate is valid
// for anyone. signer must come from CASigner for the same certType, the host
// key never signs a login and the user key never vouches for a server.
func SignCertificate(
	ca *db.SSHCA,
	signer ssh.Signer,
	pubKey string,
	principals []string,
	keyID string,
	ttl time.Duration,
	certType uint32,
	limits Limits,
) (*ssh.Certificate, error) {
	if len(principals) == 0 || len(principals) > maxPrincipals {
		return nil, &RefusedError{fmt.Sprintf("a certificate takes 1 to %d principals, got %d",
			maxPrincipals, len(principals))}
	}

	key, err := parseUserKey(pubKey)
	if err != nil {
		return nil, err
	}

	var serial uint64
	if err := binary.Read(rand.Reader, binary.BigEndian, &serial); err != nil {
		return nil, fmt.Errorf("failed to generate serial: %w", err)
	}

	// Backdated for clock skew.
	cert := &ssh.Certificate{
		Key:             key,
		Serial:          serial,
		KeyId:           keyID,
		ValidPrincipals: principals,
		ValidAfter:      UnixUint64(time.Now().Add(-time.Minute).Unix()),
	}

	if certType == ssh.HostCert {
		cert.CertType = ssh.HostCert
		ttl = ca.HostTtl
	} else {
		cert.CertType = ssh.UserCert
		ttl = UserTTL(ca, ttl)
		cert.Permissions = userPermissions(limits)
	}
	cert.ValidBefore = UnixUint64(time.Now().Add(ttl).Unix())

	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}
	return cert, nil
}

// UserTTL falls back to the CA's default, also when asked for over the max.
func UserTTL(ca *db.SSHCA, ttl time.Duration) time.Duration {
	return boundTTL(ttl, ca.UserDefaultTtl, ca.UserMaxTtl)
}

func boundTTL(ttl, defaultTTL, maxTTL time.Duration) time.Duration {
	if ttl <= 0 || ttl > maxTTL {
		return defaultTTL
	}
	return ttl
}

func userPermissions(limits Limits) ssh.Permissions {
	perms := ssh.Permissions{Extensions: maps.Clone(userExtensions), CriticalOptions: map[string]string{}}
	if limits.ForceCommand != "" {
		perms.CriticalOptions["force-command"] = limits.ForceCommand
		// ssh -N opens no session, so the command never runs and forwarding
		// would be a free tunnel. A user rc runs first.
		perms.Extensions = map[string]string{"permit-pty": ""}
	}
	if limits.SourceAddress != "" {
		perms.CriticalOptions["source-address"] = limits.SourceAddress
	}
	return perms
}

// SourceAddresses cleans the list: sshd and nokkud split on commas and trim
// nothing, so a space or typo would refuse whoever the entries before it miss.
func SourceAddresses(list string) (string, error) {
	var entries []string
	for entry := range strings.SplitSeq(list, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" || slices.Contains(entries, entry) {
			continue
		}
		if net.ParseIP(entry) == nil {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				return "", fmt.Errorf("%q is neither an address nor a CIDR", entry)
			}
		}
		entries = append(entries, entry)
	}
	return strings.Join(entries, ","), nil
}

// NormalizeKey drops options and comment, so two lines of one key compare equal.
func NormalizeKey(authorizedKey string) (string, error) {
	key, err := parseUserKey(authorizedKey)
	if err != nil {
		return "", err
	}
	return MarshalKey(key), nil
}

func parseUserKey(authorizedKey string) (ssh.PublicKey, error) {
	key, err := ParsePublicKey(authorizedKey)
	if err != nil {
		return nil, &RefusedError{"failed to parse public key: " + err.Error()}
	}
	if err := acceptedKey(key); err != nil {
		return nil, &RefusedError{err.Error()}
	}
	return key, nil
}

// acceptedKey takes what nk and nokkud make and hardware keys, no RSA or DSA.
func acceptedKey(key ssh.PublicKey) error {
	switch key.Type() {
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoED25519,
		ssh.KeyAlgoSKECDSA256, ssh.KeyAlgoSKED25519:
		return nil
	}
	return fmt.Errorf("public key type %q is not accepted, use ECDSA or Ed25519", key.Type())
}

func UnixUint64(t int64) uint64 {
	if t < 0 {
		return 0
	}
	return uint64(t)
}

func TimeFromUnix(t uint64) time.Time {
	if t > math.MaxInt64 {
		return time.Unix(math.MaxInt64, 0)
	}
	return time.Unix(int64(t), 0)
}
