package crypto

import "fmt"

type RotatingCipher struct {
	primary   Cipher
	fallbacks []Cipher
}

func NewRotatingCipher(primary Cipher, fallbacks ...Cipher) (*RotatingCipher, error) {
	if primary == nil {
		return nil, fmt.Errorf("primary cipher is required")
	}
	clean := make([]Cipher, 0, len(fallbacks))
	for _, fallback := range fallbacks {
		if fallback != nil {
			clean = append(clean, fallback)
		}
	}
	return &RotatingCipher{primary: primary, fallbacks: clean}, nil
}

func (r *RotatingCipher) Encrypt(plaintext []byte) ([]byte, error) {
	return r.primary.Encrypt(plaintext)
}

func (r *RotatingCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	plaintext, err := r.primary.Decrypt(ciphertext)
	if err == nil {
		return plaintext, nil
	}
	for _, fallback := range r.fallbacks {
		plaintext, fallbackErr := fallback.Decrypt(ciphertext)
		if fallbackErr == nil {
			return plaintext, nil
		}
	}
	return nil, err
}
