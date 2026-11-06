package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/mizuchilabs/kata/fsutil"

	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/cli/internal/state"
	"github.com/nokku-sh/nokku/internal/tpm"
)

// SetupKey writes nokku.pub. A new key drops the certificates of the old one.
func SetupKey(s *state.State) error {
	pub, err := identityKey(s)
	if err != nil {
		return err
	}

	key := bytes.TrimSpace(cryptossh.MarshalAuthorizedKey(pub))
	old, readErr := os.ReadFile(paths.PubKeyFile())
	if readErr == nil && bytes.HasPrefix(old, key) {
		return nil
	}
	if err = fsutil.WriteFile(paths.PubKeyFile(), authorizedKeyLine(key), 0o600); err != nil {
		return err
	}
	if readErr != nil {
		return nil
	}
	slog.Warn("the ssh key changed, this machine signs in again")
	return CleanupCerts(nil)
}

func identityKey(s *state.State) (cryptossh.PublicKey, error) {
	// A security key is hardware too, so --require-tpm takes it.
	if s.SecurityKey {
		return SecurityKey()
	}
	signer, err := newSSHSigner(s.RequireTPM)
	if err != nil {
		return nil, err
	}
	defer func() { _ = signer.Close() }()
	return cryptossh.NewPublicKey(signer.Public())
}

// SecurityKey is the public key of the security key handle ssh_config points at.
func SecurityKey() (cryptossh.PublicKey, error) {
	handle := paths.SecurityKeyFile()
	if !fsutil.FileExists(handle) || !fsutil.FileExists(handle+".pub") {
		return nil, errors.New("the security key file is gone, run nk login --security-key")
	}
	data, err := os.ReadFile(handle + ".pub")
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := cryptossh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("the security key file: %w", err)
	}
	if !isSecurityKey(pub) {
		return nil, fmt.Errorf("the security key file holds a %s key, run nk logout, then nk login --security-key",
			pub.Type())
	}
	return pub, nil
}

func isSecurityKey(pub cryptossh.PublicKey) bool {
	t := pub.Type()
	return t == cryptossh.KeyAlgoSKED25519 || t == cryptossh.KeyAlgoSKECDSA256
}

// A TPM when one is usable, otherwise a software key wrapped to this machine.
func newSSHSigner(requireTPM bool) (tpm.Signer, error) {
	return tpm.NewSigner(tpm.SignerOptions{
		StatePath:  paths.SSHSignerFile(),
		RequireTPM: requireTPM,
		Recreate:   true,
	})
}

func authorizedKeyLine(key []byte) []byte {
	return fmt.Appendf(bytes.Clone(key), " %s\n", keyComment())
}

// The hostname is the comment, so an operator can tell where a key came from.
func keyComment() string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	return hostname + "@nokku"
}

func PubKey() (string, error) {
	data, err := os.ReadFile(paths.PubKeyFile())
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(data)), nil
}
