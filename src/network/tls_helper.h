#ifndef P2P_TLS_HELPER_H
#define P2P_TLS_HELPER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include "../crypto/classic.h"

// ============================================
// CONSTANTS
// ============================================
#define TLS_HANDSHAKE_TIMEOUT_MS  5000
#define TLS_MAX_PLAINTEXT_SIZE    65536

// ============================================
// TLS STATE
// ============================================
typedef enum {
    TLS_STATE_INIT = 0,
    TLS_STATE_HANDSHAKE,
    TLS_STATE_ESTABLISHED,
    TLS_STATE_ERROR,
    TLS_STATE_CLOSED
} tls_state_t;

// ============================================
// TLS SESSION CONTEXT
// ============================================
typedef struct {
    // Socket
    int fd;
    tls_state_t state;
    bool is_client;
    
    // Ephemeral X25519 keypair (per-session)
    uint8_t local_pk[CRYPTO_KX_PK_SIZE];
    uint8_t local_sk[CRYPTO_KX_SK_SIZE];
    uint8_t remote_pk[CRYPTO_KX_PK_SIZE];
    
    // Derived session keys
    uint8_t tx_key[CRYPTO_KX_SESSION_SIZE];  // Our send key
    uint8_t rx_key[CRYPTO_KX_SESSION_SIZE];  // Our receive key
    
    // Nonce counters (prevent replay)
    uint64_t tx_nonce_counter;
    uint64_t rx_nonce_counter;
    
    // Statistics
    uint64_t bytes_encrypted;
    uint64_t bytes_decrypted;
    uint32_t auth_failures;
} tls_context_t;

// ============================================
// CERTIFICATE (long-term identity)
// ============================================
typedef struct {
    uint8_t identity_pk[CRYPTO_SIGN_PK_SIZE];   // Ed25519 public key
    uint8_t identity_sk[CRYPTO_SIGN_SK_SIZE];   // Ed25519 secret key
    bool valid;
} tls_certificate_t;

// ============================================
// SESSION API
// ============================================
int  tls_context_init(tls_context_t* ctx);
void tls_context_cleanup(tls_context_t* ctx);

// Handshake (call one, not both)
int tls_handshake_client(tls_context_t* ctx, int fd);
int tls_handshake_server(tls_context_t* ctx, int fd);

// Encrypted send/recv (drop-in replacement for send/recv)
ssize_t tls_send(tls_context_t* ctx, const void* data, size_t len);
ssize_t tls_recv(tls_context_t* ctx, void* buf, size_t buf_len);

// ============================================
// CERTIFICATE API
// ============================================
int  tls_cert_init(tls_certificate_t* cert);
void tls_cert_cleanup(tls_certificate_t* cert);

// Sign an ephemeral key with identity key
int tls_cert_sign_key(const tls_certificate_t* cert,
                      const uint8_t ephemeral_pk[CRYPTO_KX_PK_SIZE],
                      uint8_t sig[CRYPTO_SIGN_SIZE]);

// Verify a signed ephemeral key
int tls_cert_verify_key(const uint8_t identity_pk[CRYPTO_SIGN_PK_SIZE],
                        const uint8_t ephemeral_pk[CRYPTO_KX_PK_SIZE],
                        const uint8_t sig[CRYPTO_SIGN_SIZE]);

// ============================================
// STATUS
// ============================================
const char* tls_state_string(tls_state_t state);
bool tls_is_established(const tls_context_t* ctx);
void tls_print_info(const tls_context_t* ctx);

#endif // P2P_TLS_HELPER_H