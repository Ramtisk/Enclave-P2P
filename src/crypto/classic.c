#include "classic.h"
#include "../common/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================
// LIBSODIUM CHECK
// ============================================
// We implement a software fallback when libsodium is not available.
// In production, always link libsodium for security.

#ifdef USE_LIBSODIUM
#include <sodium.h>
#else
// ============================================
// SOFTWARE FALLBACK (minimal implementation)
// These are NOT cryptographically audited.
// Use libsodium in production.
// ============================================

// ChaCha20 quarter-round
#define QR(a, b, c, d) do { \
    a += b; d ^= a; d = (d << 16) | (d >> 16); \
    c += d; b ^= c; b = (b << 12) | (b >> 20); \
    a += b; d ^= a; d = (d << 8)  | (d >> 24); \
    c += d; b ^= c; b = (b << 7)  | (b >> 25); \
} while(0)

static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    memcpy(x, in, 64);
    
    for (int i = 0; i < 10; i++) {
        // Column rounds
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        // Diagonal rounds
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }
    
    for (int i = 0; i < 16; i++) {
        out[i] = x[i] + in[i];
    }
}

static void chacha20_encrypt(uint8_t* out, const uint8_t* in, size_t len,
                              const uint8_t key[32], const uint8_t nonce[12],
                              uint32_t counter) {
    uint32_t state[16];
    
    // "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    // Key
    for (int i = 0; i < 8; i++) {
        state[4 + i] = ((uint32_t)key[i*4]) | ((uint32_t)key[i*4+1] << 8) |
                        ((uint32_t)key[i*4+2] << 16) | ((uint32_t)key[i*4+3] << 24);
    }
    
    // Counter + nonce
    state[12] = counter;
    for (int i = 0; i < 3; i++) {
        state[13 + i] = ((uint32_t)nonce[i*4]) | ((uint32_t)nonce[i*4+1] << 8) |
                         ((uint32_t)nonce[i*4+2] << 16) | ((uint32_t)nonce[i*4+3] << 24);
    }
    
    size_t offset = 0;
    while (offset < len) {
        uint32_t keystream[16];
        chacha20_block(keystream, state);
        state[12]++; // Increment counter
        
        uint8_t* ks = (uint8_t*)keystream;
        size_t block_len = (len - offset) < 64 ? (len - offset) : 64;
        
        for (size_t i = 0; i < block_len; i++) {
            out[offset + i] = in[offset + i] ^ ks[i];
        }
        offset += block_len;
    }
}

// Poly1305 one-time authenticator (simplified)
// Reference: RFC 7539 Section 2.5
static void poly1305_mac(uint8_t tag[16], const uint8_t* msg, size_t len,
                          const uint8_t key[32]) {
    // Simplified: use first 16 bytes as r, next 16 as s
    // This is a minimal stub — real Poly1305 needs 130-bit arithmetic
    // For correctness, use libsodium
    
    // Accumulator (simplified — treats data as blocks)
    uint64_t acc[3] = {0, 0, 0};
    const uint8_t* r = key;
    const uint8_t* s = key + 16;
    
    // Simple hash for fallback (NOT real Poly1305)
    for (size_t i = 0; i < len; i++) {
        acc[0] += msg[i];
        acc[1] += acc[0];
        acc[2] ^= acc[1];
        acc[0] = (acc[0] << 1) | (acc[0] >> 63);
    }
    
    // Mix with r and s
    acc[0] ^= ((uint64_t)r[0] | ((uint64_t)r[1] << 8) | 
               ((uint64_t)r[2] << 16) | ((uint64_t)r[3] << 24));
    acc[1] ^= ((uint64_t)s[0] | ((uint64_t)s[1] << 8) | 
               ((uint64_t)s[2] << 16) | ((uint64_t)s[3] << 24));
    
    memcpy(tag, acc, 16);
}

// Software RNG fallback
static void randombytes_fallback(uint8_t* buf, size_t len) {
    FILE* f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t read = fread(buf, 1, len, f);
        fclose(f);
        if (read == len) return;
    }
    // Last resort
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
}

#endif // USE_LIBSODIUM

// ============================================
// INITIALIZATION
// ============================================

int crypto_init(void) {
#ifdef USE_LIBSODIUM
    if (sodium_init() < 0) {
        LOG_FATAL("crypto: libsodium initialization failed");
        return -1;
    }
    LOG_INFO("crypto: libsodium initialized (version: %s)", sodium_version_string());
#else
    LOG_WARN("crypto: Running WITHOUT libsodium — software fallback only!");
    LOG_WARN("crypto: This is NOT secure for production use!");
    srand((unsigned)time(NULL));
#endif
    return 0;
}

// ============================================
// RANDOM
// ============================================

void crypto_random_bytes(uint8_t* buf, size_t len) {
#ifdef USE_LIBSODIUM
    randombytes_buf(buf, len);
#else
    randombytes_fallback(buf, len);
#endif
}

// ============================================
// CHACHA20-POLY1305 AEAD
// ============================================

int crypto_aead_encrypt(uint8_t* ciphertext, size_t* ciphertext_len,
                        const uint8_t* plaintext, size_t plaintext_len,
                        const uint8_t* ad, size_t ad_len,
                        const uint8_t nonce[CRYPTO_AEAD_NONCE_SIZE],
                        const uint8_t key[CRYPTO_AEAD_KEY_SIZE]) {
#ifdef USE_LIBSODIUM
    unsigned long long ct_len;
    int ret = crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext, &ct_len,
        plaintext, plaintext_len,
        ad, ad_len,
        NULL, nonce, key);
    if (ciphertext_len) *ciphertext_len = (size_t)ct_len;
    return ret;
#else
    // Fallback: ChaCha20 encrypt + Poly1305 tag
    (void)ad; (void)ad_len;
    
    // Generate Poly1305 key from first ChaCha20 block
    uint8_t poly_key[32];
    memset(poly_key, 0, 32);
    chacha20_encrypt(poly_key, poly_key, 32, key, nonce, 0);
    
    // Encrypt starting from counter 1
    chacha20_encrypt(ciphertext, plaintext, plaintext_len, key, nonce, 1);
    
    // Compute tag over ciphertext
    poly1305_mac(ciphertext + plaintext_len, ciphertext, plaintext_len, poly_key);
    
    if (ciphertext_len) *ciphertext_len = plaintext_len + CRYPTO_AEAD_TAG_SIZE;
    return 0;
#endif
}

int crypto_aead_decrypt(uint8_t* plaintext, size_t* plaintext_len,
                        const uint8_t* ciphertext, size_t ciphertext_len,
                        const uint8_t* ad, size_t ad_len,
                        const uint8_t nonce[CRYPTO_AEAD_NONCE_SIZE],
                        const uint8_t key[CRYPTO_AEAD_KEY_SIZE]) {
#ifdef USE_LIBSODIUM
    unsigned long long pt_len;
    int ret = crypto_aead_chacha20poly1305_ietf_decrypt(
        plaintext, &pt_len,
        NULL,
        ciphertext, ciphertext_len,
        ad, ad_len,
        nonce, key);
    if (plaintext_len) *plaintext_len = (size_t)pt_len;
    return ret;
#else
    (void)ad; (void)ad_len;
    
    if (ciphertext_len < CRYPTO_AEAD_TAG_SIZE) return -1;
    
    size_t ct_only_len = ciphertext_len - CRYPTO_AEAD_TAG_SIZE;
    
    // Verify tag
    uint8_t poly_key[32];
    memset(poly_key, 0, 32);
    chacha20_encrypt(poly_key, poly_key, 32, key, nonce, 0);
    
    uint8_t computed_tag[16];
    poly1305_mac(computed_tag, ciphertext, ct_only_len, poly_key);
    
    // Constant-time comparison
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= computed_tag[i] ^ ciphertext[ct_only_len + i];
    }
    if (diff != 0) {
        LOG_WARN("crypto: AEAD decryption failed — tag mismatch");
        return -1;
    }
    
    // Decrypt
    chacha20_encrypt(plaintext, ciphertext, ct_only_len, key, nonce, 1);
    if (plaintext_len) *plaintext_len = ct_only_len;
    return 0;
#endif
}

void crypto_aead_keygen(uint8_t key[CRYPTO_AEAD_KEY_SIZE]) {
#ifdef USE_LIBSODIUM
    crypto_aead_chacha20poly1305_ietf_keygen(key);
#else
    crypto_random_bytes(key, CRYPTO_AEAD_KEY_SIZE);
#endif
}

// ============================================
// ED25519 SIGNATURES
// ============================================

int crypto_sign_keypair(uint8_t pk[CRYPTO_SIGN_PK_SIZE],
                        uint8_t sk[CRYPTO_SIGN_SK_SIZE]) {
#ifdef USE_LIBSODIUM
    return crypto_sign_ed25519_keypair(pk, sk);
#else
    // Fallback: generate random keys (NOT real Ed25519)
    LOG_WARN("crypto: Ed25519 not available without libsodium");
    crypto_random_bytes(pk, CRYPTO_SIGN_PK_SIZE);
    crypto_random_bytes(sk, CRYPTO_SIGN_SK_SIZE);
    // Copy pk into last 32 bytes of sk (libsodium convention)
    memcpy(sk + 32, pk, 32);
    return 0;
#endif
}

int crypto_sign(uint8_t* sig, size_t* sig_len,
                const uint8_t* msg, size_t msg_len,
                const uint8_t sk[CRYPTO_SIGN_SK_SIZE]) {
#ifdef USE_LIBSODIUM
    unsigned long long sl;
    int ret = crypto_sign_ed25519_detached(sig, &sl, msg, msg_len, sk);
    if (sig_len) *sig_len = (size_t)sl;
    return ret;
#else
    // Fallback: HMAC-like signature (NOT Ed25519)
    (void)msg_len;
    uint64_t acc = 0;
    for (size_t i = 0; i < msg_len; i++) {
        acc = acc * 31 + msg[i];
        acc ^= ((uint64_t)sk[i % CRYPTO_SIGN_SK_SIZE]) << (i % 8);
    }
    memset(sig, 0, CRYPTO_SIGN_SIZE);
    memcpy(sig, &acc, 8);
    memcpy(sig + 8, sk, 24); // Include part of sk for uniqueness
    // Hash again
    for (int i = 0; i < CRYPTO_SIGN_SIZE; i++) {
        sig[i] ^= (uint8_t)(acc >> (i % 8));
    }
    if (sig_len) *sig_len = CRYPTO_SIGN_SIZE;
    return 0;
#endif
}

int crypto_sign_verify(const uint8_t* sig,
                       const uint8_t* msg, size_t msg_len,
                       const uint8_t pk[CRYPTO_SIGN_PK_SIZE]) {
#ifdef USE_LIBSODIUM
    return crypto_sign_ed25519_verify_detached(sig, msg, msg_len, pk);
#else
    // Fallback: cannot verify without real Ed25519
    (void)sig; (void)msg; (void)msg_len; (void)pk;
    LOG_WARN("crypto: Signature verification not available without libsodium");
    return 0; // Accept all (INSECURE)
#endif
}

// ============================================
// X25519 KEY EXCHANGE
// ============================================

int crypto_kx_keypair(uint8_t pk[CRYPTO_KX_PK_SIZE],
                      uint8_t sk[CRYPTO_KX_SK_SIZE]) {
#ifdef USE_LIBSODIUM
    return crypto_box_keypair(pk, sk);
#else
    crypto_random_bytes(sk, CRYPTO_KX_SK_SIZE);
    crypto_random_bytes(pk, CRYPTO_KX_PK_SIZE);
    return 0;
#endif
}

int crypto_kx_session_keys(uint8_t rx_key[CRYPTO_KX_SESSION_SIZE],
                           uint8_t tx_key[CRYPTO_KX_SESSION_SIZE],
                           const uint8_t client_pk[CRYPTO_KX_PK_SIZE],
                           const uint8_t client_sk[CRYPTO_KX_SK_SIZE],
                           const uint8_t server_pk[CRYPTO_KX_PK_SIZE],
                           bool is_client) {
#ifdef USE_LIBSODIUM
    if (is_client) {
        return crypto_kx_client_session_keys(rx_key, tx_key,
                                              client_pk, client_sk, server_pk);
    } else {
        return crypto_kx_server_session_keys(rx_key, tx_key,
                                              client_pk, client_sk, server_pk);
    }
#else
    // Fallback: simple XOR-based key derivation (NOT secure)
    for (int i = 0; i < CRYPTO_KX_SESSION_SIZE; i++) {
        rx_key[i] = client_sk[i] ^ server_pk[i];
        tx_key[i] = client_pk[i] ^ server_pk[i % CRYPTO_KX_PK_SIZE];
    }
    if (!is_client) {
        // Swap rx/tx for server
        uint8_t tmp[CRYPTO_KX_SESSION_SIZE];
        memcpy(tmp, rx_key, CRYPTO_KX_SESSION_SIZE);
        memcpy(rx_key, tx_key, CRYPTO_KX_SESSION_SIZE);
        memcpy(tx_key, tmp, CRYPTO_KX_SESSION_SIZE);
    }
    return 0;
#endif
}

// ============================================
// MEMORY UTILITIES
// ============================================

void crypto_memzero(void* buf, size_t len) {
#ifdef USE_LIBSODIUM
    sodium_memzero(buf, len);
#else
    volatile uint8_t* p = (volatile uint8_t*)buf;
    while (len--) *p++ = 0;
#endif
}

int crypto_memcmp(const void* a, const void* b, size_t len) {
#ifdef USE_LIBSODIUM
    return sodium_memcmp(a, b, len);
#else
    const uint8_t* pa = (const uint8_t*)a;
    const uint8_t* pb = (const uint8_t*)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= pa[i] ^ pb[i];
    }
    return diff != 0 ? -1 : 0;
#endif
}