#ifndef P2P_IDENTITY_TYPES_H
#define P2P_IDENTITY_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../../crypto/classic.h"
#include "../../common/config.h"

/*  ============================================
    IDENTITY CONSTANTS

    Note: Defines version, fingerprint size, maximum group identities,
    and sizes for zero-knowledge proof fields.
    ============================================ */
#define IDENTITY_VERSION 1
#define IDENTITY_FINGERPRINT_SIZE 16
#define MAX_GROUP_IDENTITIES MAX_GROUPS
#define ZKP_CHALLENGE_SIZE 32
#define ZKP_RESPONSE_SIZE 64

/*  ============================================
    PEER IDENTITY (long-term)

    Note: Represents the long-term identity of a peer.
    Contains Ed25519 signing keypair, human-readable peer ID,
    truncated fingerprint, and metadata.
    ============================================ */
typedef struct
{
    uint8_t sign_pk[CRYPTO_SIGN_PK_SIZE];
    uint8_t sign_sk[CRYPTO_SIGN_SK_SIZE];
    char peer_id[MAX_ID_LENGTH];
    uint8_t fingerprint[IDENTITY_FINGERPRINT_SIZE];
    uint64_t created_at;
    uint8_t version;
    bool initialized;
} peer_identity_t;

/*  ============================================
    GROUP EPHEMERAL IDENTITY

    Note: Per-group ephemeral keypair for unlinkability.
    Different groups cannot correlate the same user.
    Contains ephemeral Ed25519 and X25519 keypairs,
    fingerprint, ephemeral ID, and a binding signature
    proving ownership by the long-term key.
    ============================================ */
typedef struct
{
    char group_id[MAX_ID_LENGTH];
    uint8_t sign_pk[CRYPTO_SIGN_PK_SIZE];
    uint8_t sign_sk[CRYPTO_SIGN_SK_SIZE];
    uint8_t kx_pk[CRYPTO_KX_PK_SIZE];
    uint8_t kx_sk[CRYPTO_KX_SK_SIZE];
    uint8_t fingerprint[IDENTITY_FINGERPRINT_SIZE];
    char ephemeral_id[MAX_ID_LENGTH];
    uint8_t binding_sig[CRYPTO_SIGN_SIZE];
    uint64_t created_at;
    bool active;
} group_identity_t;

/*  ============================================
    ZERO-KNOWLEDGE PROOF (Schnorr-like)

    Note: Proves "I know the secret key for this public key"
    without revealing the secret key.
    Uses non-interactive Fiat-Shamir heuristic.
    ============================================ */
typedef struct
{
    uint8_t commitment[CRYPTO_SIGN_PK_SIZE];
    uint8_t challenge[ZKP_CHALLENGE_SIZE];
    uint8_t response[ZKP_RESPONSE_SIZE];
} zkp_proof_t;

/*  ============================================
    IDENTITY STORE

    Note: Holds the peer's own long-term identity,
    all group ephemeral identities, and the path
    for persistent storage on disk.
    ============================================ */
typedef struct
{
    peer_identity_t self;
    group_identity_t groups[MAX_GROUP_IDENTITIES];
    int group_count;
    char storage_path[256];
    bool loaded;
} identity_store_t;

#endif