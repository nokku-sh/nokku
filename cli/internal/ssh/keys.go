package ssh

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/mizuchilabs/kata/fsutil"

	"github.com/nokku-sh/nokku/cli/internal/enclave"
	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/internal/tpm"
)

// TPM or Secure Enclave when one is usable, otherwise a software key wrapped to this machine.
func newSSHSigner(requireTPM bool) (tpm.Signer, error) {
	return tpm.NewSigner(tpm.SignerOptions{
		StatePath:  paths.SSHSignerFile(),
		RequireTPM: requireTPM,
		Recreate:   true,
		Enclave:    enclave.New(),
	})
}

// SetupKey drops the cached certificates when the identity changed.
func SetupKey(requireTPM bool) error {
	signer, err := newSSHSigner(requireTPM)
	if err != nil {
		return err
	}
	defer func() { _ = signer.Close() }()

	pub, err := cryptossh.NewPublicKey(signer.Public())
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
	if readErr == nil {
		slog.Warn("ssh identity changed, fetching new certificates")
		return CleanupCerts(nil)
	}
	return nil
}

// The hostname is the comment, so an operator can tell where a key came from.
func authorizedKeyLine(key []byte) []byte {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	return fmt.Appendf(bytes.Clone(key), " %s@nokku\n", hostname)
}

func PubKey() (string, error) {
	data, err := os.ReadFile(paths.PubKeyFile())
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(data)), nil
}
