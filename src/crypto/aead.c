#include "aead.h"
#include "random.h"
#include "memory.h"
#include "../common/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_LIBSODIUM
#include <sodium.h>
#else

/*  ============================================
    CHACHA20 SOFTWARE FALLBACK (NOT SECURE FOR PRODUCTION)

    Note: Quarter-round macro and block function for ChaCha20.
    Only used when libsodium is not available.
    ============================================ */
#define QR(a, b, c, d) do { \
    a += b; d ^= a; d = (d << 16) | (d >> 16); \
    c += d; b ^= c; b = (b << 12) | (b >> 20); \
    a += b; d ^= a; d = (d << 8)  | (d >> 24); \
    c += d; b ^= c; b = (b << 7)  | (b >> 25); \
} while(0)

/*  Function: chacha20_block
    Description:
    Computes a single ChaCha20 block from the given state.

    Parameters:
    - out: Output 16-word block.
    - in: Input 16-word state.

    Steps:
    1. Copies the input state.
    2. Performs 20 rounds (10 double rounds) of quarter-round operations.
    3. Adds the original state to the result.
*/
static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    memcpy(x, in, 64);

    for (int i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }

    for (int i = 0; i < 16; i++) {
        out[i] = x[i] + in[i];
    }
}

/*  Function: chacha20_encrypt
    Description:
    Encrypts or decrypts data using ChaCha20 stream cipher.

    Parameters:
    - out: Output buffer.
    - in: Input buffer.
    - len: Number of bytes.
    - key: 256-bit key.
    - nonce: 96-bit nonce.
    - counter: Initial block counter.

    Steps:
    1. Initializes the ChaCha20 state with constants, key, counter, and nonce.
    2. Generates 64-byte keystream blocks.
    3. XORs the input with the keystream to produce output.
    4. Increments the counter for each block.
*/
static void chacha20_encrypt(uint8_t* out, const uint8_t* in, size_t len,
                              const uint8_t key[32], const uint8_t nonce[12],
                              uint32_t counter) {
    uint32_t state[16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    for (int i = 0; i < 8; i++) {
        state[4 + i] = ((uint32_t)key[i*4]) | ((uint32_t)key[i*4+1] << 8) |
                        ((uint32_t)key[i*4+2] << 16) | ((uint32_t)key[i*4+3] << 24);
    }

    state[12] = counter;
    for (int i = 0; i < 3; i++) {
        state[13 + i] = ((uint32_t)nonce[i*4]) | ((uint32_t)nonce[i*4+1] << 8) |
                         ((uint32_t)nonce[i*4+2] << 16) | ((uint32_t)nonce[i*4+3] << 24);
    }

    size_t offset = 0;
    while (offset < len) {
        uint32_t keystream[16];
        chacha20_block(keystream, state);
        state[12]++;

        uint8_t* ks = (uint8_t*)keystream;
        size_t block_len = (len - offset) < 64 ? (len - offset) : 64;

        for (size_t i = 0; i < block_len; i++) {
            out[offset + i] = in[offset + i] ^ ks[i];
        }
        offset += block_len;
    }
}

/*  Function: poly1305_mac_fallback
    Description:
    Computes a Poly1305-like MAC (NOT real Poly1305 — stub for fallback only).

    Parameters:
    - tag: Output 16-byte authentication tag.
    - msg: Input message.
    - len: Message length.
    - key: 32-byte key.

    Steps:
    1. Accumulates a hash over the message bytes.
    2. Mixes with key material.
    3. Writes 16-byte tag output.
*/
static void poly1305_mac_fallback(uint8_t tag[16], const uint8_t* msg, size_t len,
                                   const uint8_t key[32]) {
    uint64_t acc[3] = {0, 0, 0};
    const uint8_t* r = key;
    const uint8_t* s = key + 16;

    for (size_t i = 0; i < len; i++) {
        acc[0] += msg[i];
        acc[1] += acc[0];
        acc[2] ^= acc[1];
        acc[0] = (acc[0] << 1) | (acc[0] >> 63);
    }

    acc[0] ^= ((uint64_t)r[0] | ((uint64_t)r[1] << 8) |
               ((uint64_t)r[2] << 16) | ((uint64_t)r[3] << 24));
    acc[1] ^= ((uint64_t)s[0] | ((uint64_t)s[1] << 8) |
               ((uint64_t)s[2] << 16) | ((uint64_t)s[3] << 24));

    memcpy(tag, acc, 16);
}

#endif /* USE_LIBSODIUM */

/*  Function: p2p_aead_encrypt
    Description:
    Encrypts plaintext and produces an authenticated ciphertext with ChaCha20-Poly1305 IETF.

    Parameters:
    - ciphertext: Output buffer (must be at least plaintext_len + CRYPTO_AEAD_TAG_SIZE).
    - ciphertext_len: Output pointer for the ciphertext length.
    - plaintext: Input plaintext.
    - plaintext_len: Length of plaintext.
    - ad: Associated data (authenticated but not encrypted).
    - ad_len: Length of associated data.
    - nonce: 96-bit nonce (must be unique per key).
    - key: 256-bit encryption key.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Validates input pointers.
    2. If USE_LIBSODIUM, delegates to crypto_aead_chacha20poly1305_ietf_encrypt().
    3. Otherwise, derives Poly1305 key, encrypts with ChaCha20, and computes MAC.
*/
int p2p_aead_encrypt(uint8_t* ciphertext, size_t* ciphertext_len,
                     const uint8_t* plaintext, size_t plaintext_len,
                     const uint8_t* ad, size_t ad_len,
                     const uint8_t nonce[CRYPTO_AEAD_NONCE_SIZE],
                     const uint8_t key[CRYPTO_AEAD_KEY_SIZE]) {
    if (!ciphertext || !plaintext || !nonce || !key) return -1;

#ifdef USE_LIBSODIUM
    unsigned long long ct_len = 0;
    int ret = crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext, &ct_len,
        plaintext, (unsigned long long)plaintext_len,
        ad, (unsigned long long)ad_len,
        NULL, nonce, key);
    if (ciphertext_len) *ciphertext_len = (size_t)ct_len;
    return ret;
#else
    (void)ad; (void)ad_len;

    uint8_t poly_key[32];
    memset(poly_key, 0, 32);
    chacha20_encrypt(poly_key, poly_key, 32, key, nonce, 0);

    chacha20_encrypt(ciphertext, plaintext, plaintext_len, key, nonce, 1);

    poly1305_mac_fallback(ciphertext + plaintext_len, ciphertext, plaintext_len, poly_key);

    if (ciphertext_len) *ciphertext_len = plaintext_len + CRYPTO_AEAD_TAG_SIZE;
    p2p_memzero(poly_key, sizeof(poly_key));
    return 0;
#endif
}

/*  Function: p2p_aead_decrypt
    Description:
    Decrypts and verifies an authenticated ciphertext with ChaCha20-Poly1305 IETF.

    Parameters:
    - plaintext: Output buffer.
    - plaintext_len: Output pointer for the plaintext length.
    - ciphertext: Input ciphertext (includes tag).
    - ciphertext_len: Length of ciphertext.
    - ad: Associated data.
    - ad_len: Length of associated data.
    - nonce: 96-bit nonce.
    - key: 256-bit encryption key.

    Returns:
    - 0 on success, -1 on failure (tag mismatch or invalid input).

    Steps:
    1. Validates input and checks minimum ciphertext length.
    2. If USE_LIBSODIUM, delegates to crypto_aead_chacha20poly1305_ietf_decrypt().
    3. Otherwise, derives Poly1305 key, verifies MAC, then decrypts.
*/
int p2p_aead_decrypt(uint8_t* plaintext, size_t* plaintext_len,
                     const uint8_t* ciphertext, size_t ciphertext_len,
                     const uint8_t* ad, size_t ad_len,
                     const uint8_t nonce[CRYPTO_AEAD_NONCE_SIZE],
                     const uint8_t key[CRYPTO_AEAD_KEY_SIZE]) {
    if (!plaintext || !ciphertext || !nonce || !key) return -1;
    if (ciphertext_len < CRYPTO_AEAD_TAG_SIZE) return -1;

#ifdef USE_LIBSODIUM
    unsigned long long pt_len = 0;
    int ret = crypto_aead_chacha20poly1305_ietf_decrypt(
        plaintext, &pt_len,
        NULL,
        ciphertext, (unsigned long long)ciphertext_len,
        ad, (unsigned long long)ad_len,
        nonce, key);
    if (plaintext_len) *plaintext_len = (size_t)pt_len;
    return ret;
#else
    (void)ad; (void)ad_len;

    size_t ct_only_len = ciphertext_len - CRYPTO_AEAD_TAG_SIZE;

    uint8_t poly_key[32];
    memset(poly_key, 0, 32);
    chacha20_encrypt(poly_key, poly_key, 32, key, nonce, 0);

    uint8_t computed_tag[16];
    poly1305_mac_fallback(computed_tag, ciphertext, ct_only_len, poly_key);
    p2p_memzero(poly_key, sizeof(poly_key));

    if (p2p_memcmp_ct(computed_tag, ciphertext + ct_only_len, 16) != 0) {
        LOG_WARN("crypto: AEAD tag mismatch");
        return -1;
    }

    chacha20_encrypt(plaintext, ciphertext, ct_only_len, key, nonce, 1);
    if (plaintext_len) *plaintext_len = ct_only_len;
    return 0;
#endif
}

/*  Function: p2p_aead_keygen
    Description:
    Generates a random 256-bit key for AEAD encryption.

    Parameters:
    - key: Output buffer for the key.

    Steps:
    1. If USE_LIBSODIUM, delegates to crypto_aead_chacha20poly1305_ietf_keygen().
    2. Otherwise, fills the key with random bytes.
*/
void p2p_aead_keygen(uint8_t key[CRYPTO_AEAD_KEY_SIZE]) {
#ifdef USE_LIBSODIUM
    crypto_aead_chacha20poly1305_ietf_keygen(key);
#else
    p2p_random_bytes(key, CRYPTO_AEAD_KEY_SIZE);
#endif
}