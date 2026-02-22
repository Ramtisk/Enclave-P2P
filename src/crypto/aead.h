#ifndef P2P_CRYPTO_AEAD_H
#define P2P_CRYPTO_AEAD_H

#include <stdint.h>
#include <stddef.h>

/*  ============================================
    AEAD CONSTANTS

    Note: Sizes for ChaCha20-Poly1305 IETF AEAD.
    ============================================ */
#define CRYPTO_AEAD_KEY_SIZE   32
#define CRYPTO_AEAD_NONCE_SIZE 12
#define CRYPTO_AEAD_TAG_SIZE   16

/*  ============================================
    CHACHA20-POLY1305 AEAD API

    Note: Authenticated encryption with associated data.
    Uses libsodium if available, otherwise a software fallback (NOT secure for production).
    ============================================ */
int p2p_aead_encrypt(uint8_t* ciphertext, size_t* ciphertext_len,
                     const uint8_t* plaintext, size_t plaintext_len,
                     const uint8_t* ad, size_t ad_len,
                     const uint8_t nonce[CRYPTO_AEAD_NONCE_SIZE],
                     const uint8_t key[CRYPTO_AEAD_KEY_SIZE]);

int p2p_aead_decrypt(uint8_t* plaintext, size_t* plaintext_len,
                     const uint8_t* ciphertext, size_t ciphertext_len,
                     const uint8_t* ad, size_t ad_len,
                     const uint8_t nonce[CRYPTO_AEAD_NONCE_SIZE],
                     const uint8_t key[CRYPTO_AEAD_KEY_SIZE]);

void p2p_aead_keygen(uint8_t key[CRYPTO_AEAD_KEY_SIZE]);

#endif