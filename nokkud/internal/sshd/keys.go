package sshd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/internal/tpm"
	"github.com/nokku-sh/nokku/nokkud/internal/hostcerts"
	"github.com/nokku-sh/nokku/nokkud/internal/paths"
)

// hostKeySalt namespaces the host key. Salt registry: internal/README.md.
const hostKeySalt = "nokku-daemon-host"

// Tests swap it.
var newHostSigner = tpm.NewSigner

// The host key is not the enrollment anchor, so an identity change just gets a fresh key and a renewed cert.
func loadHostKey() (ssh.Signer, io.Closer, error) {
	signer, err := newHostSigner(tpm.SignerOptions{
		Salt:      []byte(hostKeySalt),
		StatePath: paths.HostSignerStateFile(),
		Recreate:  true,
	})
	if err != nil {
		return nil, nil, err
	}
	if err = writeHostPubKey(signer); err != nil {
		_ = signer.Close()
		return nil, nil, err
	}
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		_ = signer.Close()
		return nil, nil, fmt.Errorf("sshd: host key signer: %w", err)
	}
	return sshSigner, signer, nil
}

// Without a certificate clients see the bare key and its fingerprint prompt, so a missing one is worth a line.
func withHostCert(key ssh.Signer) ssh.Signer {
	cert, err := hostcerts.Load()
	if errors.Is(err, fs.ErrNotExist) {
		slog.Debug("no host certificate yet, serving the bare host key")
		return key
	}
	if err == nil {
		var signer ssh.Signer
		if signer, err = ssh.NewCertSigner(cert, key); err == nil {
			return signer
		}
	}
	slog.Warn("host certificate unusable, serving the bare host key", "error", err)
	return key
}

// A cert for a previous key is dropped so the sync renews it.
func writeHostPubKey(signer tpm.Signer) error {
	pub, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("sshd: encode host public key: %w", err)
	}
	pubData := ssh.MarshalAuthorizedKey(pub)

	old, readErr := os.ReadFile(paths.HostKeyPub())
	if readErr == nil && bytes.Equal(bytes.TrimSpace(old), bytes.TrimSpace(pubData)) {
		return nil
	}
	// #nosec G306 - a host public key is world-readable by design.
	if err = os.WriteFile(paths.HostKeyPub(), pubData, 0o644); err != nil {
		return fmt.Errorf("sshd: write host public key: %w", err)
	}
	if readErr == nil {
		_ = os.Remove(paths.HostKeyCert())
	}
	return nil
}
