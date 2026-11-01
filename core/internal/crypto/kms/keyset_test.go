package kms

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

var _ tink.AEAD = fakeKEK{}

// fakeKEK tags the blob with its key byte, so a wrong KEK fails loudly.
type fakeKEK struct{ id byte }

func (f fakeKEK) Encrypt(plaintext, _ []byte) ([]byte, error) {
	return append([]byte{f.id}, plaintext...), nil
}

func (f fakeKEK) Decrypt(ciphertext, _ []byte) ([]byte, error) {
	if len(ciphertext) == 0 || ciphertext[0] != f.id {
		return nil, errors.New("wrong KEK")
	}
	return ciphertext[1:], nil
}

func TestWrapUnwrapRoundtrip(t *testing.T) {
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	data, err := wrap(handle, fakeKEK{id: 1})
	require.NoError(t, err)

	loaded, err := unwrap(data, fakeKEK{id: 1})
	require.NoError(t, err)

	// The persisted bytes must be sufficient to reconstruct a working cipher.
	primitive, err := aead.New(loaded)
	require.NoError(t, err)
	plaintext := []byte("ca private key")
	ciphertext, err := primitive.Encrypt(plaintext, nil)
	require.NoError(t, err)
	decrypted, err := primitive.Decrypt(ciphertext, nil)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestUnwrapWrongKEKFails(t *testing.T) {
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)
	data, err := wrap(handle, fakeKEK{id: 1})
	require.NoError(t, err)

	_, err = unwrap(data, fakeKEK{id: 2})
	require.Error(t, err, "a wrong KEK must fail at boot, not run with a broken encryptor")
}

func TestUnwrapCorruptDataFails(t *testing.T) {
	_, err := unwrap([]byte("not a keyset"), fakeKEK{id: 1})
	require.Error(t, err)
}
