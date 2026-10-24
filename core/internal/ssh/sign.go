package ssh

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"maps"
	"math"
	"net"
	"strings"
	"time"
	"uuid"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// maxPrincipals is how many principals OpenSSH reads from one certificate.
const maxPrincipals = 256

// LoginPrincipal lets one subject log in as one account on one server. Hosts compare it as a whole string.
func LoginPrincipal(subjectID, targetID, username string) string {
	return subjectID + "@" + targetID + ":" + username
}

// Principal is a LoginPrincipal taken apart.
type Principal struct {
	SubjectID string
	TargetID  string
	Username  string
}

// ParseLoginPrincipal is for the core only. The ids are UUIDs, so "@" or ":" in a username cannot shift the split.
func ParseLoginPrincipal(s string) (Principal, bool) {
	subject, rest, ok := strings.Cut(s, "@")
	if !ok {
		return Principal{}, false
	}
	target, username, ok := strings.Cut(rest, ":")
	if !ok || username == "" {
		return Principal{}, false
	}
	if _, err := uuid.Parse(subject); err != nil {
		return Principal{}, false
	}
	if _, err := uuid.Parse(target); err != nil {
		return Principal{}, false
	}
	return Principal{SubjectID: subject, TargetID: target, Username: username}, true
}

// SignCertificate refuses an empty principal list, such a certificate is valid for anyone.
func SignCertificate(
	ca *db.SSHCA,
	pubKey string,
	principals []string,
	keyID string,
	ttl time.Duration,
	certType uint32,
) (*ssh.Certificate, error) {
	if len(principals) == 0 || len(principals) > maxPrincipals {
		return nil, fmt.Errorf("a certificate takes 1 to %d principals, got %d", maxPrincipals, len(principals))
	}
	// The host key never signs a login, the user key never vouches for a server.
	private := ca.PrivateKey
	if certType == ssh.HostCert {
		private = ca.HostPrivateKey
	}
	signer, err := getSigner(private.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to create CA signer: %w", err)
	}

	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	if err := acceptedKey(key); err != nil {
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
		ttl = boundTTL(ttl, ca.HostDefaultTtl, ca.HostMaxTtl)
	} else {
		cert.CertType = ssh.UserCert
		ttl = UserTTL(ca, ttl)
		cert.Permissions = userPermissions(ca)
	}
	cert.ValidBefore = UnixUint64(time.Now().Add(ttl).Unix())

	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}
	return cert, nil
}

// UserTTL falls back to the CA's default when nothing is asked, or more than the CA allows.
func UserTTL(ca *db.SSHCA, ttl time.Duration) time.Duration {
	return boundTTL(ttl, ca.UserDefaultTtl, ca.UserMaxTtl)
}

func boundTTL(ttl, defaultTTL, maxTTL time.Duration) time.Duration {
	if ttl <= 0 || ttl > maxTTL {
		return defaultTTL
	}
	return ttl
}

// userExtensions is what every user certificate permits. What a session may really do is the host's call: the
// daemon config where nokkud runs, sshd_config where it does not.
var userExtensions = map[string]string{
	"permit-pty":              "",
	"permit-user-rc":          "",
	"permit-port-forwarding":  "",
	"permit-agent-forwarding": "",
}

func userPermissions(ca *db.SSHCA) ssh.Permissions {
	perms := ssh.Permissions{Extensions: maps.Clone(userExtensions), CriticalOptions: map[string]string{}}
	if ca.ForceCommand != "" {
		perms.CriticalOptions["force-command"] = ca.ForceCommand
	}
	if ca.SourceAddress != "" {
		perms.CriticalOptions["source-address"] = ca.SourceAddress
	}
	return perms
}

// SourceAddresses tidies a list of addresses and CIDRs into the form a certificate carries. sshd and nokkud split
// it on commas and trim nothing, so a space or a typo would refuse everyone the entries before it do not match.
func SourceAddresses(list string) (string, error) {
	var entries []string
	for entry := range strings.SplitSeq(list, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
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

// acceptedKey takes the key types nk and nokkud make, and hardware security keys. RSA and DSA are refused.
func acceptedKey(key ssh.PublicKey) error {
	switch key.Type() {
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoED25519,
		ssh.KeyAlgoSKECDSA256, ssh.KeyAlgoSKED25519:
		return nil
	}
	return fmt.Errorf("public key type %q is not accepted, use ECDSA or Ed25519", key.Type())
}

// UnixUint64 is a certificate validity bound, never before the epoch.
func UnixUint64(t int64) uint64 {
	if t < 0 {
		return 0
	}
	return uint64(t)
}

// TimeFromUnix reads a certificate validity bound.
func TimeFromUnix(t uint64) time.Time {
	if t > math.MaxInt64 {
		return time.Unix(math.MaxInt64, 0)
	}
	return time.Unix(int64(t), 0)
}
