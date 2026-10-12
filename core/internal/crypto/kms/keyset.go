package kms

import (
	"bytes"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func wrap(handle *keyset.Handle, kek tink.AEAD) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := handle.Write(keyset.NewBinaryWriter(buf), kek); err != nil {
		return nil, fmt.Errorf("failed to wrap keyset: %w", err)
	}
	return buf.Bytes(), nil
}

func unwrap(data []byte, kek tink.AEAD) (*keyset.Handle, error) {
	handle, err := keyset.Read(keyset.NewBinaryReader(bytes.NewReader(data)), kek)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to unwrap keyset, NOKKU_SECRET or KMS_URI does not match the stored keys or the KMS did not answer: %w",
			err,
		)
	}
	return handle, nil
}
