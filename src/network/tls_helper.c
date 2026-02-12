#include "tls_helper.h"
#include "../common/logging.h"
#include "../crypto/classic.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

// ============================================
// Our "TLS" is a custom encrypted transport using
// libsodium primitives (ChaCha20-Poly1305 + X25519).
//
// Protocol:
// 1. Both sides send their X25519 public key (32 bytes)
// 2. Both derive rx_key and tx_key
// 3. All subsequent messages: [4-byte len][nonce][ciphertext+tag]
//
// This gives us authenticated encryption with
// forward secrecy (ephemeral keys per session).
// ============================================

// ============================================
// WIRE FORMAT
// ============================================
// Handshake: 32 bytes (X25519 public key)
// Frame:     [uint32_t len][12-byte nonce][ciphertext (len - 12 bytes)]
//            ciphertext includes 16-byte Poly1305 tag

#define TLS_FRAME_HEADER_SIZE 4
#define TLS_NONCE_SIZE        CRYPTO_AEAD_NONCE_SIZE
#define TLS_TAG_SIZE          CRYPTO_AEAD_TAG_SIZE
#define TLS_MAX_FRAME_SIZE    (65536 + TLS_NONCE_SIZE + TLS_TAG_SIZE)

// ============================================
// SESSION MANAGEMENT
// ============================================

int tls_context_init(tls_context_t* ctx) {
    memset(ctx, 0, sizeof(tls_context_t));
    
    // Generate ephemeral keypair
    if (crypto_kx_keypair(ctx->local_pk, ctx->local_sk) != 0) {
        LOG_ERROR("tls: Failed to generate ephemeral keypair");
        return -1;
    }
    
    ctx->state = TLS_STATE_INIT;
    ctx->tx_nonce_counter = 0;
    ctx->rx_nonce_counter = 0;
    ctx->fd = -1;
    
    LOG_TRACE("tls: Context initialized with ephemeral keys");
    return 0;
}

void tls_context_cleanup(tls_context_t* ctx) {
    // Zero sensitive material
    crypto_memzero(ctx->local_sk, sizeof(ctx->local_sk));
    crypto_memzero(ctx->tx_key, sizeof(ctx->tx_key));
    crypto_memzero(ctx->rx_key, sizeof(ctx->rx_key));
    
    ctx->state = TLS_STATE_CLOSED;
    ctx->fd = -1;
    
    LOG_TRACE("tls: Context cleaned up (keys zeroed)");
}

// ============================================
// HANDSHAKE
// ============================================
// Simple 1-RTT key exchange:
// Client → Server: client_pk (32 bytes)
// Server → Client: server_pk (32 bytes)
// Both derive session keys using X25519

static int tls_send_raw(int fd, const void* data, size_t len) {
    const uint8_t* ptr = (const uint8_t*)data;
    size_t remaining = len;
    
    while (remaining > 0) {
        ssize_t sent = send(fd, ptr, remaining, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (sent == 0) return -1;
        ptr += sent;
        remaining -= (size_t)sent;
    }
    return 0;
}

static int tls_recv_raw(int fd, void* buf, size_t len, int timeout_ms) {
    uint8_t* ptr = (uint8_t*)buf;
    size_t remaining = len;
    
    struct timeval tv;
    if (timeout_ms > 0) {
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    
    while (remaining > 0) {
        ssize_t received = recv(fd, ptr, remaining, 0);
        if (received < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (received == 0) return -1; // EOF
        ptr += received;
        remaining -= (size_t)received;
    }
    
    // Reset timeout
    if (timeout_ms > 0) {
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    
    return 0;
}

int tls_handshake_client(tls_context_t* ctx, int fd) {
    ctx->fd = fd;
    ctx->is_client = true;
    ctx->state = TLS_STATE_HANDSHAKE;
    
    LOG_DEBUG("tls: Starting client handshake (fd=%d)", fd);
    
    // Step 1: Send our public key
    if (tls_send_raw(fd, ctx->local_pk, CRYPTO_KX_PK_SIZE) != 0) {
        LOG_ERROR("tls: Failed to send client public key");
        ctx->state = TLS_STATE_ERROR;
        return -1;
    }
    
    // Step 2: Receive server's public key
    if (tls_recv_raw(fd, ctx->remote_pk, CRYPTO_KX_PK_SIZE, 
                     TLS_HANDSHAKE_TIMEOUT_MS) != 0) {
        LOG_ERROR("tls: Failed to receive server public key");
        ctx->state = TLS_STATE_ERROR;
        return -1;
    }
    
    // Step 3: Derive session keys (client side)
    if (crypto_kx_session_keys(ctx->rx_key, ctx->tx_key,
                                ctx->local_pk, ctx->local_sk,
                                ctx->remote_pk, true) != 0) {
        LOG_ERROR("tls: Key derivation failed");
        ctx->state = TLS_STATE_ERROR;
        return -1;
    }
    
    // Step 4: Send verification token
    // Encrypt a known string to verify keys match
    uint8_t verify_pt[32] = "ENCLAVE_TLS_VERIFY_TOKEN_V1\0\0\0\0\0";
    uint8_t verify_ct[32 + TLS_TAG_SIZE];
    uint8_t verify_nonce[TLS_NONCE_SIZE];
    memset(verify_nonce, 0, TLS_NONCE_SIZE);
    
    size_t ct_len;
    if (crypto_aead_encrypt(verify_ct, &ct_len,
                            verify_pt, 32,
                            NULL, 0,
                            verify_nonce, ctx->tx_key) != 0) {
        LOG_ERROR("tls: Verification encrypt failed");
        ctx->state = TLS_STATE_ERROR;
        return -1;
    }
    
    if (tls_send_raw(fd, verify_ct, ct_len) != 0) {
        LOG_ERROR("tls: Failed to send verification");
        ctx->state = TLS_STATE_ERROR;
        return -1;
    }
    
    // Step 5: Receive and verify server's token
    uint8_t server_ct[32 + TLS_TAG_SIZE];
    if (tls_recv_raw(fd, server_ct, 32 + TLS_TAG_SIZE,
                     TLS_HANDSHAKE_TIMEOUT_MS) != 0) {
        LOG_ERROR("tls: Failed to receive server verification");
        ctx->state = TLS_STATE_ERROR;
        return -1;
    }
    
    uint8_t server_pt[32];
    size_t pt_len;
    if (crypto_aead_decrypt(server_pt, &pt_len,
                            server_ct, 32 + TLS_TAG_SIZE,
                            NULL, 0,
                            verify_nonce, ctx->rx_key) != 0) {
        LOG_ERROR("tls: Server verification FAILED — keys don't match!");
        ctx->state = TLS_STATE_ERROR;
        return -1;
    }
    
    if (memcmp(server_pt, verify_pt, 32) != 0) {
        LOG_ERROR("tls: Server verification token mismatch");
        ctx->state = TLS_STATE_ERROR;
        return -1;
    }
    
    ctx->state = TLS_STATE_ESTABLISHED;
    LOG_INFO("tls: Client handshake complete (encrypted channel established)");
    return 0;
}

int tls_handshake_server(tls_context_t* ctx, int fd) {
    ctx->fd = fd;
    ctx->is_client = false;
    ctx->state = TLS_STATE_HANDSHAKE;
    
    LOG_DEBUG("tls: Starting server handshake (fd=%d)", fd);
    
    // Step 1: Receive client's public key
    if (tls_recv_raw(fd, ctx->remote_pk, CRYPTO_KX_PK_SIZE,
                     TLS_HANDSHAKE_TIMEOUT_MS) != 0) {
        LOG_ERROR("tls: Failed to receive client public key");
        ctx->state = TLS_STATE_ERROR;
        return -1;
    }
    
    // Step 2: Send our public key
    if (tls_send_raw(fd, ctx->local_pk, CRYPTO_KX_PK_SIZE) != 0) {
        LOG_ERROR("tls: Failed to send server public key");
        ctx->state = TLS_STATE_ERROR;
        return -1;
    }
    
    // Step 3: Derive session keys (server side)
    if (crypto_kx_session_keys(ctx->rx_key, ctx->tx_key,
                                ctx->local_pk, ctx->local_sk,
                                ctx->remote_pk, false) != 0) {
        LOG_ERROR("tls: Key derivation failed");
        ctx->state = TLS_STATE_ERROR;
        return -1;
    }
    
    // Step 4: Receive and verify client's token
    uint8_t client_ct[32 + TLS_TAG_SIZE];
    if (tls_recv_raw(fd, client_ct, 32 + TLS_TAG_SIZE,
                     TLS_HANDSHAKE_TIMEOUT_MS) != 0) {
        LOG_ERROR("tls: Failed to receive client verification");
        ctx->state = TLS_STATE_ERROR;
        return -1;
    }
    
    uint8_t verify_nonce[TLS_NONCE_SIZE];
    memset(verify_nonce, 0, TLS_NONCE_SIZE);
    
    uint8_t client_pt[32];
    size_t pt_len;
    if (crypto_aead_decrypt(client_pt, &pt_len,
                            client_ct, 32 + TLS_TAG_SIZE,
                            NULL, 0,
                            verify_nonce, ctx->rx_key) != 0) {
        LOG_ERROR("tls: Client verification FAILED — keys don't match!");
        ctx->state = TLS_STATE_ERROR;
        return -1;
    }
    
    uint8_t expected[32] = "ENCLAVE_TLS_VERIFY_TOKEN_V1\0\0\0\0\0";
    if (memcmp(client_pt, expected, 32) != 0) {
        LOG_ERROR("tls: Client verification token mismatch");
        ctx->state = TLS_STATE_ERROR;
        return -1;
    }
    
    // Step 5: Send our verification token
    uint8_t verify_ct[32 + TLS_TAG_SIZE];
    size_t ct_len;
    if (crypto_aead_encrypt(verify_ct, &ct_len,
                            expected, 32,
                            NULL, 0,
                            verify_nonce, ctx->tx_key) != 0) {
        LOG_ERROR("tls: Server verification encrypt failed");
        ctx->state = TLS_STATE_ERROR;
        return -1;
    }
    
    if (tls_send_raw(fd, verify_ct, ct_len) != 0) {
        LOG_ERROR("tls: Failed to send server verification");
        ctx->state = TLS_STATE_ERROR;
        return -1;
    }
    
    ctx->state = TLS_STATE_ESTABLISHED;
    LOG_INFO("tls: Server handshake complete (encrypted channel established)");
    return 0;
}

// ============================================
// ENCRYPTED SEND/RECV
// ============================================
// Frame format: [uint32_t payload_len][12-byte nonce][ciphertext+tag]
// payload_len = nonce_size + ciphertext_size + tag_size

static void build_nonce(uint8_t nonce[TLS_NONCE_SIZE], uint64_t counter, 
                        bool is_tx) {
    memset(nonce, 0, TLS_NONCE_SIZE);
    // First byte: direction flag (prevents nonce reuse if both sides
    // happen to have same counter)
    nonce[0] = is_tx ? 0x01 : 0x02;
    // Bytes 4-11: counter (little-endian)
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (uint8_t)(counter >> (i * 8));
    }
}

ssize_t tls_send(tls_context_t* ctx, const void* data, size_t len) {
    if (ctx->state != TLS_STATE_ESTABLISHED) {
        LOG_WARN("tls: Cannot send — not established (state=%d)", ctx->state);
        return -1;
    }
    if (len == 0) return 0;
    if (len > TLS_MAX_PLAINTEXT_SIZE) {
        LOG_ERROR("tls: Message too large (%zu > %d)", len, TLS_MAX_PLAINTEXT_SIZE);
        return -1;
    }
    
    // Build nonce from counter
    uint8_t nonce[TLS_NONCE_SIZE];
    build_nonce(nonce, ctx->tx_nonce_counter++, true);
    
    // Encrypt
    size_t ct_len;
    uint8_t ciphertext[TLS_MAX_FRAME_SIZE];
    
    if (crypto_aead_encrypt(ciphertext, &ct_len,
                            (const uint8_t*)data, len,
                            NULL, 0,
                            nonce, ctx->tx_key) != 0) {
        LOG_ERROR("tls: Encryption failed");
        return -1;
    }
    
    // Build frame: [len][nonce][ciphertext+tag]
    uint32_t frame_payload = (uint32_t)(TLS_NONCE_SIZE + ct_len);
    
    // Send header
    uint8_t header[TLS_FRAME_HEADER_SIZE];
    header[0] = (uint8_t)(frame_payload & 0xFF);
    header[1] = (uint8_t)((frame_payload >> 8) & 0xFF);
    header[2] = (uint8_t)((frame_payload >> 16) & 0xFF);
    header[3] = (uint8_t)((frame_payload >> 24) & 0xFF);
    
    if (tls_send_raw(ctx->fd, header, TLS_FRAME_HEADER_SIZE) != 0) {
        return -1;
    }
    
    // Send nonce
    if (tls_send_raw(ctx->fd, nonce, TLS_NONCE_SIZE) != 0) {
        return -1;
    }
    
    // Send ciphertext
    if (tls_send_raw(ctx->fd, ciphertext, ct_len) != 0) {
        return -1;
    }
    
    ctx->bytes_encrypted += len;
    return (ssize_t)len;
}

ssize_t tls_recv(tls_context_t* ctx, void* buf, size_t buf_len) {
    if (ctx->state != TLS_STATE_ESTABLISHED) {
        LOG_WARN("tls: Cannot recv — not established (state=%d)", ctx->state);
        return -1;
    }
    
    // Read frame header
    uint8_t header[TLS_FRAME_HEADER_SIZE];
    if (tls_recv_raw(ctx->fd, header, TLS_FRAME_HEADER_SIZE, 0) != 0) {
        return -1; // Connection closed or error
    }
    
    uint32_t frame_payload = (uint32_t)header[0] |
                              ((uint32_t)header[1] << 8) |
                              ((uint32_t)header[2] << 16) |
                              ((uint32_t)header[3] << 24);
    
    if (frame_payload < TLS_NONCE_SIZE + TLS_TAG_SIZE ||
        frame_payload > TLS_MAX_FRAME_SIZE) {
        LOG_ERROR("tls: Invalid frame size: %u", frame_payload);
        ctx->state = TLS_STATE_ERROR;
        return -1;
    }
    
    // Read nonce
    uint8_t nonce[TLS_NONCE_SIZE];
    if (tls_recv_raw(ctx->fd, nonce, TLS_NONCE_SIZE, 0) != 0) {
        return -1;
    }
    
    // Read ciphertext + tag
    size_t ct_len = frame_payload - TLS_NONCE_SIZE;
    uint8_t ciphertext[TLS_MAX_FRAME_SIZE];
    if (tls_recv_raw(ctx->fd, ciphertext, ct_len, 0) != 0) {
        return -1;
    }
    
    // Decrypt
    size_t pt_len;
    if (crypto_aead_decrypt((uint8_t*)buf, &pt_len,
                            ciphertext, ct_len,
                            NULL, 0,
                            nonce, ctx->rx_key) != 0) {
        LOG_ERROR("tls: Decryption FAILED — possible tampering!");
        ctx->auth_failures++;
        ctx->state = TLS_STATE_ERROR;
        return -1;
    }
    
    if (pt_len > buf_len) {
        LOG_ERROR("tls: Decrypted data exceeds buffer (%zu > %zu)", pt_len, buf_len);
        return -1;
    }
    
    ctx->bytes_decrypted += pt_len;
    ctx->rx_nonce_counter++;
    return (ssize_t)pt_len;
}

// ============================================
// CERTIFICATE MANAGEMENT (self-signed identity)
// ============================================
// Each peer has a long-term Ed25519 identity key.
// During handshake, they sign their ephemeral X25519 key
// to prove identity.

int tls_cert_init(tls_certificate_t* cert) {
    memset(cert, 0, sizeof(tls_certificate_t));
    
    // Generate Ed25519 identity keypair
    if (crypto_sign_keypair(cert->identity_pk, cert->identity_sk) != 0) {
        LOG_ERROR("tls: Failed to generate identity keypair");
        return -1;
    }
    
    cert->valid = true;
    
    LOG_INFO("tls: Identity certificate generated");
    return 0;
}

void tls_cert_cleanup(tls_certificate_t* cert) {
    crypto_memzero(cert->identity_sk, sizeof(cert->identity_sk));
    cert->valid = false;
}

int tls_cert_sign_key(const tls_certificate_t* cert,
                      const uint8_t ephemeral_pk[CRYPTO_KX_PK_SIZE],
                      uint8_t sig[CRYPTO_SIGN_SIZE]) {
    if (!cert->valid) return -1;
    
    size_t sig_len;
    return crypto_sign(sig, &sig_len,
                       ephemeral_pk, CRYPTO_KX_PK_SIZE,
                       cert->identity_sk);
}

int tls_cert_verify_key(const uint8_t identity_pk[CRYPTO_SIGN_PK_SIZE],
                        const uint8_t ephemeral_pk[CRYPTO_KX_PK_SIZE],
                        const uint8_t sig[CRYPTO_SIGN_SIZE]) {
    return crypto_sign_verify(sig, ephemeral_pk, CRYPTO_KX_PK_SIZE, identity_pk);
}

// ============================================
// STATUS
// ============================================

const char* tls_state_string(tls_state_t state) {
    switch (state) {
        case TLS_STATE_INIT:        return "INIT";
        case TLS_STATE_HANDSHAKE:   return "HANDSHAKE";
        case TLS_STATE_ESTABLISHED: return "ESTABLISHED";
        case TLS_STATE_ERROR:       return "ERROR";
        case TLS_STATE_CLOSED:      return "CLOSED";
        default:                    return "UNKNOWN";
    }
}

bool tls_is_established(const tls_context_t* ctx) {
    return ctx->state == TLS_STATE_ESTABLISHED;
}

void tls_print_info(const tls_context_t* ctx) {
    LOG_INFO("╔════════════════════════════════════════╗");
    LOG_INFO("║           TLS SESSION INFO             ║");
    LOG_INFO("╠════════════════════════════════════════╣");
    LOG_INFO("║  State:        %-24s ║", tls_state_string(ctx->state));
    LOG_INFO("║  Role:         %-24s ║", ctx->is_client ? "Client" : "Server");
    LOG_INFO("║  FD:           %-24d ║", ctx->fd);
    LOG_INFO("║  TX Nonce:     %-24lu ║", ctx->tx_nonce_counter);
    LOG_INFO("║  RX Nonce:     %-24lu ║", ctx->rx_nonce_counter);
    LOG_INFO("║  Encrypted:    %-20lu B ║", ctx->bytes_encrypted);
    LOG_INFO("║  Decrypted:    %-20lu B ║", ctx->bytes_decrypted);
    LOG_INFO("║  Auth Fails:   %-24u ║", ctx->auth_failures);
    LOG_INFO("╚════════════════════════════════════════╝");
}