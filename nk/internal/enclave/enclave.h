// C view of enclave.swift. Every function but nk_enclave_available returns 0
// on success and fills out, or 1 and fills err. The caller frees both.
#include <stddef.h>
#include <stdint.h>

int nk_enclave_available(void);

int nk_enclave_create(int software, uint8_t **out, size_t *out_len, char **err);

int nk_enclave_public(int software, const uint8_t *blob, size_t blob_len,
                      uint8_t **out, size_t *out_len, char **err);

int nk_enclave_sign(int software, const uint8_t *blob, size_t blob_len,
                    const uint8_t *digest, size_t digest_len,
                    uint8_t **out, size_t *out_len, char **err);
