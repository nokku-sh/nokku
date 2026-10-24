package tpm

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/mizuchilabs/kata/fsutil"
)

var (
	// errNoState signals that no signer state exists at the configured path.
	errNoState = errors.New("tpm: no signer state")
	// errBadState signals a state file that is there but does not parse.
	errBadState = errors.New("tpm: the signer state does not parse")
)

// Data is the TPM key file, the enclave blob, or the wrapped private key of a software key. PubKey only shows which
// key a state file holds, nothing reads it to sign.
type state struct {
	Method string `json:"method"`
	PubKey string `json:"pubkey"`
	Salt   []byte `json:"salt,omitempty"`
	Nonce  []byte `json:"nonce,omitempty"`
	Data   []byte `json:"data,omitempty"`
}

func loadState(path string) (*state, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errNoState
	}
	if err != nil {
		return nil, fmt.Errorf("tpm: read signer state: %w", err)
	}
	var st state
	if err = json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("%w: %w", errBadState, err)
	}
	return &st, nil
}

// A software key lives only in this file, so the write is atomic and synced to disk.
func saveState(path string, st *state) error {
	if err := fsutil.SaveJSON(path, st, 0o600); err != nil {
		return fmt.Errorf("tpm: write signer state: %w", err)
	}
	return nil
}

// lockState keeps two processes from creating different keys for one state file. The returned func releases it.
func lockState(statePath string) (func(), error) {
	f, err := os.OpenFile(statePath+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("tpm: open the state lock: %w", err)
	}
	if err = flock(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("tpm: lock the signer state: %w", err)
	}
	return func() { _ = f.Close() }, nil
}
