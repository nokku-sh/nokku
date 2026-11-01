package crypto

import "encoding/binary"

// Sealed is a secret as stored. Only Keyset.Seal makes one, Keyset.Open reads
// it. String and MarshalJSON render "" so it never reaches a log or an answer.
type Sealed []byte

// AAD names where a sealed secret is stored, so a ciphertext copied to another
// row, column or workspace fails to open.
type AAD struct {
	Table     string
	Column    string
	Workspace string
	// Row is the rest of the primary key, its parts joined by "/".
	Row string
}

func (Sealed) String() string { return "" }

func (Sealed) MarshalJSON() ([]byte, error) { return []byte(`""`), nil }

// Bytes length-prefixes every field, so no two AADs encode the same.
func (a AAD) Bytes() []byte {
	var b []byte
	for _, part := range []string{a.Table, a.Column, a.Workspace, a.Row} {
		b = binary.AppendUvarint(b, uint64(len(part)))
		b = append(b, part...)
	}
	return b
}
