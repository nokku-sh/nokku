package paths

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func EnsureDirs() error {
	if _, err := os.UserHomeDir(); err != nil {
		return fmt.Errorf("cannot resolve the home directory: %w", err)
	}
	for _, dir := range []string{ConfigDir(), SSHCertDir()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("cannot create directory %s: %w", dir, err)
		}
	}
	return nil
}

// ConfigDir avoids the macOS dir, its space would hit every ssh_config line.
func ConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "nk")
}

func SSHUserConfig() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh", "config")
}

func ConfigFile() string      { return filepath.Join(ConfigDir(), "config.json") }
func CacheFile() string       { return filepath.Join(ConfigDir(), "cache.json") }
func SSHConfigFile() string   { return filepath.Join(ConfigDir(), "ssh_config") }
func KnownHostsFile() string  { return filepath.Join(ConfigDir(), "known_hosts") }
func PubKeyFile() string      { return filepath.Join(ConfigDir(), "nokku.pub") }
func SSHCertDir() string      { return filepath.Join(ConfigDir(), "certs") }
func SignerStateFile() string { return filepath.Join(ConfigDir(), "signer.json") }
func SSHSignerFile() string   { return filepath.Join(ConfigDir(), "ssh-signer.json") }

// SecurityKeyFile is the key handle ssh-keygen wrote, useless without the key.
func SecurityKeyFile() string { return filepath.Join(ConfigDir(), "security-key") }

// AgentSocket is a pipe on Windows, OpenSSH speaks to agents only over pipes.
func AgentSocket() string {
	if runtime.GOOS == "windows" {
		sum := sha256.Sum256([]byte(ConfigDir()))
		return `\\.\pipe\nk-agent-` + hex.EncodeToString(sum[:6])
	}
	return filepath.Join(ConfigDir(), "agent.sock")
}

// SSHCertificate trusts the id, state.Targets drops any that is not a UUID.
func SSHCertificate(targetID string) string {
	return filepath.Join(SSHCertDir(), targetID+"-cert.pub")
}

func SSHCertificates() ([]string, error) {
	return filepath.Glob(filepath.Join(SSHCertDir(), "*-cert.pub"))
}

func RemoveConfigDir() error {
	if err := os.RemoveAll(ConfigDir()); err != nil {
		return fmt.Errorf("remove config dir: %w", err)
	}
	return nil
}
