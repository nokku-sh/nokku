//go:build integration

package db_test

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/integration/testenv"
)

func TestMain(m *testing.M) {
	// Encrypted columns need a cipher. This one keeps a ciphertext readable in tests that look at the stored bytes.
	_ = crypto.SetEncryptor(prefixCipher("enc:"))
	stop := testenv.Postgres()
	code := m.Run()
	stop()
	os.Exit(code)
}

// prefixCipher marks its output with itself, so a blob made with another prefix fails to decrypt.
type prefixCipher string

func (c prefixCipher) Encrypt(plaintext []byte) ([]byte, error) {
	return append([]byte(c), plaintext...), nil
}

func (c prefixCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	plaintext, ok := bytes.CutPrefix(ciphertext, []byte(c))
	if !ok {
		return nil, errors.New("not a ciphertext of " + string(c))
	}
	return plaintext, nil
}
