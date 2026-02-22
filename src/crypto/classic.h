#ifndef P2P_CRYPTO_CLASSIC_H
#define P2P_CRYPTO_CLASSIC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

// ============================================
// CONSTANTS (match libsodium sizes)
// ============================================

// ChaCha20-Poly1305 AEAD
#define CRYPTO_AEAD_KEY_SIZE   32   // 256-bit key
#define CRYPTO_AEAD_NONCE_SIZE 12   // 96-bit nonce (IETF)
#define CRYPTO_AEAD_TAG_SIZE   16   // 128-bit auth tag

// Ed25519 Signatures
#define CRYPTO_SIGN_PK_SIZE    32   // Public key
#define CRYPTO_SIGN_SK_SIZE    64   // Secret key (seed + pk)
#define CRYPTO_SIGN_SIZE       64   // Signature size

// X25519 Key Exchange
#define CRYPTO_KX_PK_SIZE      32   // Public key
#define CRYPTO_KX_SK_SIZE      32   // Secret key
#define CRYPTO_KX_SESSION_SIZE 32   // Session key

// ============================================
// INITIALIZATION
// ============================================
int crypto_init(void);

// ============================================
// RANDOM
// ============================================
void crypto_random_bytes(uint8_t* buf, size_t len);

// ============================================
// CHACHA20-POLY1305 AEAD
// ============================================
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

// ============================================
// ED25519 DIGITAL SIGNATURES
// ============================================
int p2p_sign_keypair(uint8_t pk[CRYPTO_SIGN_PK_SIZE],
                     uint8_t sk[CRYPTO_SIGN_SK_SIZE]);

int p2p_sign_create(uint8_t* sig, size_t* sig_len,
                    const uint8_t* msg, size_t msg_len,
                    const uint8_t sk[CRYPTO_SIGN_SK_SIZE]);

int p2p_sign_verify(const uint8_t* sig,
                    const uint8_t* msg, size_t msg_len,
                    const uint8_t pk[CRYPTO_SIGN_PK_SIZE]);

// ============================================
// X25519 KEY EXCHANGE
// ============================================
int p2p_kx_keypair(uint8_t pk[CRYPTO_KX_PK_SIZE],
                   uint8_t sk[CRYPTO_KX_SK_SIZE]);

int p2p_kx_session_keys(uint8_t rx_key[CRYPTO_KX_SESSION_SIZE],
                        uint8_t tx_key[CRYPTO_KX_SESSION_SIZE],
                        const uint8_t our_pk[CRYPTO_KX_PK_SIZE],
                        const uint8_t our_sk[CRYPTO_KX_SK_SIZE],
                        const uint8_t their_pk[CRYPTO_KX_PK_SIZE],
                        bool is_client);


// ============================================
// MEMORY UTILITIES
// ============================================
void p2p_memzero(void* buf, size_t len);
int  p2p_memcmp_ct(const void* a, const void* b, size_t len);

#endif