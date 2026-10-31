package sshd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"github.com/mizuchilabs/kata/fsutil"
	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/daemon/internal/hostcerts"
	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

// CreateHostKey gives the host a new SSH host key, a root-only file like sshd's. Every enrollment makes one.
func CreateHostKey() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("sshd: generate host key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		return fmt.Errorf("sshd: encode host key: %w", err)
	}
	if err = fsutil.WriteFile(paths.HostKey(), pem.EncodeToMemory(block), 0o600); err != nil {
		return fmt.Errorf("sshd: write host key: %w", err)
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("sshd: encode host public key: %w", err)
	}
	return writeHostPubKey(pub)
}

// A host that has no key yet gets one, the way sshd makes its keys on first boot.
func loadHostKey() (ssh.Signer, error) {
	info, err := os.Stat(paths.HostKey())
	if errors.Is(err, fs.ErrNotExist) {
		if err = CreateHostKey(); err != nil {
			return nil, err
		}
		info, err = os.Stat(paths.HostKey())
	}
	if err != nil {
		return nil, fmt.Errorf("sshd: host key: %w", err)
	}
	// Like sshd, a key others can read is refused rather than used.
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("sshd: host key %s is readable by others, it must be mode 0600", paths.HostKey())
	}
	data, err := os.ReadFile(paths.HostKey())
	if err != nil {
		return nil, fmt.Errorf("sshd: read host key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("sshd: parse host key %s: %w", paths.HostKey(), err)
	}
	if err = writeHostPubKey(signer.PublicKey()); err != nil {
		return nil, err
	}
	return signer, nil
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
func writeHostPubKey(pub ssh.PublicKey) error {
	pubData := ssh.MarshalAuthorizedKey(pub)
	old, readErr := os.ReadFile(paths.HostKeyPub())
	if readErr == nil && bytes.Equal(bytes.TrimSpace(old), bytes.TrimSpace(pubData)) {
		return nil
	}
	// #nosec G306 G703 - a host public key is world-readable by design, and the path is the daemon's own.
	if err := os.WriteFile(paths.HostKeyPub(), pubData, 0o644); err != nil {
		return fmt.Errorf("sshd: write host public key: %w", err)
	}
	if err := os.Remove(paths.HostKeyCert()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("sshd: drop the certificate of the previous host key: %w", err)
	}
	return nil
}
