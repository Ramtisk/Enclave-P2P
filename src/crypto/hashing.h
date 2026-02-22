#ifndef P2P_CRYPTO_HASHING_H
#define P2P_CRYPTO_HASHING_H

#include <stdint.h>
#include <stddef.h>

/*  ============================================
    HASHING API

    Note: Provides SHA-256 hashing, HMAC-SHA256, and HKDF-SHA256 (RFC 5869).
    SHA-256 is delegated to the chunking.c implementation.
    HMAC and HKDF are built on top of SHA-256.
    ============================================ */

extern void sha256_hash(const uint8_t* data, size_t len, uint8_t* hash_out);

void crypto_hmac_sha256(uint8_t out[32],
                        const uint8_t* key, size_t key_len,
                        const uint8_t* data, size_t data_len);

void crypto_hkdf_sha256(uint8_t* okm, size_t okm_len,
                        const uint8_t* ikm, size_t ikm_len,
                        const uint8_t* salt, size_t salt_len,
                        const uint8_t* info, size_t info_len);

#endif