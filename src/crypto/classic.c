#include "classic.h"
#include "../common/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================
// LIBSODIUM CHECK
// ============================================

#ifdef USE_LIBSODIUM
#include <sodium.h>
#else
// ============================================
// SOFTWARE FALLBACK (NOT cryptographically secure)
// Use libsodium in production!
// ============================================

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

// Poly1305 stub (NOT real — use libsodium for actual security)
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

static void randombytes_fallback(uint8_t* buf, size_t len) {
    FILE* f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t rd = fread(buf, 1, len, f);
        fclose(f);
        if (rd == len) return;
    }
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
}

#endif // USE_LIBSODIUM

// ============================================
// INITIALIZATION
// ============================================

int p2p_crypto_init(void) {
#ifdef USE_LIBSODIUM
    if (sodium_init() < 0) {
        LOG_FATAL("crypto: libsodium initialization failed");
        return -1;
    }
    LOG_INFO("crypto: libsodium %s initialized", sodium_version_string());
    LOG_INFO("crypto:   AEAD: ChaCha20-Poly1305-IETF (key=%d, nonce=%d, tag=%d)",
             crypto_aead_chacha20poly1305_ietf_KEYBYTES,
             crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
             crypto_aead_chacha20poly1305_ietf_ABYTES);
    LOG_INFO("crypto:   Sign: Ed25519 (pk=%d, sk=%d, sig=%d)",
             crypto_sign_ed25519_PUBLICKEYBYTES,
             crypto_sign_ed25519_SECRETKEYBYTES,
             crypto_sign_ed25519_BYTES);
    LOG_INFO("crypto:   KX:   X25519 (pk=%d, sk=%d, session=%d)",
             crypto_kx_PUBLICKEYBYTES,
             crypto_kx_SECRETKEYBYTES,
             crypto_kx_SESSIONKEYBYTES);
#else
    LOG_WARN("crypto: Running WITHOUT libsodium — software fallback only!");
    LOG_WARN("crypto: DO NOT use in production!");
    srand((unsigned)time(NULL));
#endif
    return 0;
}

// ============================================
// RANDOM
// ============================================

void p2p_random_bytes(uint8_t* buf, size_t len) {
#ifdef USE_LIBSODIUM
    randombytes_buf(buf, len);
#else
    randombytes_fallback(buf, len);
#endif
}

// ============================================
// CHACHA20-POLY1305 AEAD
// ============================================

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

void p2p_aead_keygen(uint8_t key[CRYPTO_AEAD_KEY_SIZE]) {
#ifdef USE_LIBSODIUM
    crypto_aead_chacha20poly1305_ietf_keygen(key);
#else
    p2p_random_bytes(key, CRYPTO_AEAD_KEY_SIZE);
#endif
}

// ============================================
// ED25519 SIGNATURES
// ============================================

int p2p_sign_keypair(uint8_t pk[CRYPTO_SIGN_PK_SIZE],
                     uint8_t sk[CRYPTO_SIGN_SK_SIZE]) {
    if (!pk || !sk) return -1;
    
#ifdef USE_LIBSODIUM
    return crypto_sign_ed25519_keypair(pk, sk);
#else
    LOG_WARN("crypto: Ed25519 stub — not real signatures");
    p2p_random_bytes(pk, CRYPTO_SIGN_PK_SIZE);
    p2p_random_bytes(sk, CRYPTO_SIGN_SK_SIZE);
    memcpy(sk + 32, pk, 32);
    return 0;
#endif
}

int p2p_sign_create(uint8_t* sig, size_t* sig_len,
                    const uint8_t* msg, size_t msg_len,
                    const uint8_t sk[CRYPTO_SIGN_SK_SIZE]) {
    if (!sig || !msg || !sk) return -1;
    
#ifdef USE_LIBSODIUM
    unsigned long long sl = 0;
    int ret = crypto_sign_ed25519_detached(sig, &sl, msg, 
                                            (unsigned long long)msg_len, sk);
    if (sig_len) *sig_len = (size_t)sl;
    return ret;
#else
    // Fallback: HMAC-like stub
    uint64_t acc = 0;
    for (size_t i = 0; i < msg_len; i++) {
        acc = acc * 31 + msg[i];
        acc ^= ((uint64_t)sk[i % CRYPTO_SIGN_SK_SIZE]) << (i % 8);
    }
    memset(sig, 0, CRYPTO_SIGN_SIZE);
    memcpy(sig, &acc, 8);
    memcpy(sig + 8, sk, 24);
    for (int i = 0; i < CRYPTO_SIGN_SIZE; i++) {
        sig[i] ^= (uint8_t)(acc >> (i % 8));
    }
    if (sig_len) *sig_len = CRYPTO_SIGN_SIZE;
    return 0;
#endif
}

int p2p_sign_verify(const uint8_t* sig,
                    const uint8_t* msg, size_t msg_len,
                    const uint8_t pk[CRYPTO_SIGN_PK_SIZE]) {
    if (!sig || !msg || !pk) return -1;
    
#ifdef USE_LIBSODIUM
    return crypto_sign_ed25519_verify_detached(sig, msg, 
                                                (unsigned long long)msg_len, pk);
#else
    (void)sig; (void)msg; (void)msg_len; (void)pk;
    LOG_WARN("crypto: Signature verification stub — accepts all");
    return 0;
#endif
}

// ============================================
// X25519 KEY EXCHANGE
// ============================================

int p2p_kx_keypair(uint8_t pk[CRYPTO_KX_PK_SIZE],
                   uint8_t sk[CRYPTO_KX_SK_SIZE]) {
    if (!pk || !sk) return -1;
    
#ifdef USE_LIBSODIUM
    return crypto_kx_keypair(pk, sk);
#else
    p2p_random_bytes(sk, CRYPTO_KX_SK_SIZE);
    p2p_random_bytes(pk, CRYPTO_KX_PK_SIZE);
    return 0;
#endif
}

int p2p_kx_session_keys(uint8_t rx_key[CRYPTO_KX_SESSION_SIZE],
                        uint8_t tx_key[CRYPTO_KX_SESSION_SIZE],
                        const uint8_t our_pk[CRYPTO_KX_PK_SIZE],
                        const uint8_t our_sk[CRYPTO_KX_SK_SIZE],
                        const uint8_t their_pk[CRYPTO_KX_PK_SIZE],
                        bool is_client) {
    if (!rx_key || !tx_key || !our_pk || !our_sk || !their_pk) return -1;
    
#ifdef USE_LIBSODIUM
    if (is_client) {
        return crypto_kx_client_session_keys(rx_key, tx_key,
                                              our_pk, our_sk, their_pk);
    } else {
        return crypto_kx_server_session_keys(rx_key, tx_key,
                                              our_pk, our_sk, their_pk);
    }
#else
    for (int i = 0; i < CRYPTO_KX_SESSION_SIZE; i++) {
        rx_key[i] = our_sk[i] ^ their_pk[i];
        tx_key[i] = our_pk[i] ^ their_pk[i % CRYPTO_KX_PK_SIZE];
    }
    if (!is_client) {
        uint8_t tmp[CRYPTO_KX_SESSION_SIZE];
        memcpy(tmp, rx_key, CRYPTO_KX_SESSION_SIZE);
        memcpy(rx_key, tx_key, CRYPTO_KX_SESSION_SIZE);
        memcpy(tx_key, tmp, CRYPTO_KX_SESSION_SIZE);
        p2p_memzero(tmp, CRYPTO_KX_SESSION_SIZE);
    }
    return 0;
#endif
}

// ============================================
// MEMORY UTILITIES
// ============================================

void p2p_memzero(void* buf, size_t len) {
    if (!buf || len == 0) return;
#ifdef USE_LIBSODIUM
    sodium_memzero(buf, len);
#else
    volatile uint8_t* p = (volatile uint8_t*)buf;
    while (len--) *p++ = 0;
#endif
}

int p2p_memcmp_ct(const void* a, const void* b, size_t len) {
    if (!a || !b) return -1;
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