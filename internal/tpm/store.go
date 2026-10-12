package tpm

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// errNoState signals that no signer state exists at the configured path.
var errNoState = errors.New("tpm: no signer state")

// state is the on-disk representation of a signer. TPM keys store only the
// public half, software keys also carry their wrapped private key.
type state struct {
	Method string `json:"method"`
	PubKey string `json:"pubkey"`
	Salt   []byte `json:"salt,omitempty"`
	Nonce  []byte `json:"nonce,omitempty"`
	Data   []byte `json:"data,omitempty"`
}

// loadState reads the persisted signer state. errNoState when absent.
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
		return nil, fmt.Errorf("tpm: parse signer state: %w", err)
	}
	return &st, nil
}

// saveState writes the signer state atomically and durably. A software key
// lives only in this file, so a torn write after a power cut would lose the
// machine identity.
func saveState(path string, st *state) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("tpm: serialize signer state: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".signer-*.tmp")
	if err != nil {
		return fmt.Errorf("tpm: create temp state file: %w", err)
	}
	tmpName := tmp.Name()

	// CreateTemp makes the file 0600, which the rename keeps.
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("tpm: write temp state file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("tpm: close temp state file: %w", err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("tpm: replace state file: %w", err)
	}
	return nil
}
