package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/nokku-sh/nokku/cli/internal/paths"
)

// securityKeyApp keeps nk's credentials apart from the user's own ssh keys.
const securityKeyApp = "application=ssh:nokku"

var errKeyTypeUnsupported = errors.New("the security key can't make this key type")

// EnrollSecurityKey has ssh-keygen make a key on a FIDO2 key, ssh talks to it from then on.
func EnrollSecurityKey(ctx context.Context) error {
	if _, err := SecurityKey(); err == nil {
		return nil
	}
	file := paths.SecurityKeyFile()
	// ssh-keygen would ask whether to overwrite a half-written pair.
	_ = os.Remove(file)
	_ = os.Remove(file + ".pub")

	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		return errors.New("ssh-keygen not found, install OpenSSH")
	}
	err = runKeygen(ctx, keygen, "ed25519-sk", file)
	if errors.Is(err, errKeyTypeUnsupported) {
		fmt.Fprintln(os.Stderr, "This security key has no Ed25519, making an ECDSA key instead.")
		err = runKeygen(ctx, keygen, "ecdsa-sk", file)
	}
	return err
}

// RemoveSecurityKey drops the handle, so a later enrollment makes a new key, also on another security key.
func RemoveSecurityKey() error {
	file := paths.SecurityKeyFile()
	var errs []error
	for _, f := range []string{file, file + ".pub"} {
		if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func runKeygen(ctx context.Context, keygen, keyType, file string) error {
	var stderr bytes.Buffer
	// #nosec G204 -- keygen comes from PATH, every argument is ours
	cmd := exec.CommandContext(ctx, keygen,
		"-t", keyType, "-O", securityKeyApp, "-C", keyComment(), "-N", "", "-f", file)
	// The touch and PIN prompts must reach the user, stdout stays clean for --json.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, io.MultiWriter(os.Stderr, &stderr)
	err := cmd.Run()
	if err == nil {
		return nil
	}
	out := stderr.String()
	switch {
	case strings.Contains(out, "SecurityKeyProvider"):
		hint := "this OpenSSH can't use security keys"
		if runtime.GOOS == "darwin" {
			hint += ", Apple's ssh lacks it. Install OpenSSH from Homebrew and make sure its ssh comes first in PATH"
		}
		return errors.New(hint)
	case strings.Contains(out, "not supported"):
		return errKeyTypeUnsupported
	}
	return fmt.Errorf("ssh-keygen could not make a key on the security key: %w", err)
}
