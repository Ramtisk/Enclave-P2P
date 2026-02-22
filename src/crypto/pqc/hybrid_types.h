#ifndef P2P_CRYPTO_HYBRID_TYPES_H
#define P2P_CRYPTO_HYBRID_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include "kem.h"
#include "../signing.h"
#include "../kx.h"

/*  ============================================
    HYBRID HANDSHAKE CONSTANTS

    Note: Combined X25519 classical + PQC KEM.
    Final shared secret = HKDF(x25519_ss || pqc_ss).
    ============================================ */
#define HYBRID_SHARED_SECRET_SIZE  32
#define HYBRID_HANDSHAKE_VERSION   1
#define HYBRID_FLAG_HAS_PQC        0x01

/*  ============================================
    HYBRID KEY BUNDLE

    Note: Sent during handshake — contains both classical X25519
    and PQC KEM public keys, plus an Ed25519 signature
    over both keys for authentication.
    ============================================ */
typedef struct {
    uint8_t version;
    uint8_t x25519_pk[CRYPTO_KX_PK_SIZE];
    uint8_t kem_pk[PQC_KEM_PK_SIZE];
    uint8_t identity_pk[CRYPTO_SIGN_PK_SIZE];
    uint8_t signature[CRYPTO_SIGN_SIZE];
    bool has_pqc;
} hybrid_key_bundle_t;

/*  ============================================
    HYBRID HANDSHAKE STATE

    Note: Tracks the state machine of the hybrid handshake.
    Progresses from INIT through key generation, bundle exchange,
    to ESTABLISHED or ERROR.
    ============================================ */
typedef enum {
    HYBRID_STATE_INIT = 0,
    HYBRID_STATE_KEYS_GENERATED,
    HYBRID_STATE_BUNDLE_SENT,
    HYBRID_STATE_BUNDLE_RECEIVED,
    HYBRID_STATE_ESTABLISHED,
    HYBRID_STATE_ERROR
} hybrid_state_t;

/*  ============================================
    HYBRID HANDSHAKE CONTEXT

    Note: Holds all state for a single hybrid handshake session.
    Contains our keys, peer's keys, intermediate and final shared secrets,
    KEM ciphertext, and the handshake state.
    ============================================ */
typedef struct {
    hybrid_state_t state;
    bool is_initiator;

    uint8_t x25519_pk[CRYPTO_KX_PK_SIZE];
    uint8_t x25519_sk[CRYPTO_KX_SK_SIZE];
    uint8_t kem_pk[PQC_KEM_PK_SIZE];
    uint8_t kem_sk[PQC_KEM_SK_SIZE];

    uint8_t peer_x25519_pk[CRYPTO_KX_PK_SIZE];
    uint8_t peer_kem_pk[PQC_KEM_PK_SIZE];
    uint8_t peer_identity_pk[CRYPTO_SIGN_PK_SIZE];

    uint8_t kem_ciphertext[PQC_KEM_CT_SIZE];

    uint8_t x25519_ss[CRYPTO_KX_SESSION_SIZE];
    uint8_t kem_ss[PQC_KEM_SS_SIZE];

    uint8_t rx_key[HYBRID_SHARED_SECRET_SIZE];
    uint8_t tx_key[HYBRID_SHARED_SECRET_SIZE];

    bool pqc_used;
} hybrid_handshake_t;

/*  ============================================
    WIRE FORMAT HEADER

    Note: Packed header for serializing hybrid key bundles over the network.
    - version: Protocol version.
    - flags: Bit 0 = has_pqc.
    - x25519_pk: Classical public key.
    - kem_pk_len: Length of PQC public key (0 if none).
    Followed by: kem_pk[kem_pk_len], identity_pk[32], signature[64].
    ============================================ */
typedef struct __attribute__((packed)) {
    uint8_t  version;
    uint8_t  flags;
    uint8_t  x25519_pk[32];
    uint16_t kem_pk_len;
} hybrid_bundle_header_t;

#endif