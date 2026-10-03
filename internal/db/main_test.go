package db

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/testdb"
)

func TestMain(m *testing.M) {
	testdb.Setup("db")
	// Encrypted columns need a cipher. The real one lives in crypto/kms,
	// which imports this package.
	_ = crypto.SetEncryptor(prefixCipher("enc:"))
	os.Exit(m.Run())
}

// prefixCipher marks its output with itself, so a blob made with another
// prefix fails to decrypt.
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
