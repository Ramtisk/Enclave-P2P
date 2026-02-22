#include "hybrid_handshake.h"
#include "kem.h"
#include "../signing.h"
#include "../kx.h"
#include "../memory.h"
#include "../hashing.h"
#include "../../common/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*  Function: hybrid_handshake_init
    Description:
    Initializes a hybrid handshake context, generating X25519 and KEM keypairs.

    Parameters:
    - hs: Pointer to the hybrid_handshake_t context.
    - is_initiator: True if this side initiates the handshake.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Clears the context.
    2. Sets initiator flag and state to INIT.
    3. Generates X25519 ephemeral keypair.
    4. Generates KEM keypair.
    5. Transitions to KEYS_GENERATED state.
    6. Logs initialization details.
*/
int hybrid_handshake_init(hybrid_handshake_t* hs, bool is_initiator) {
    if (!hs) return -1;

    memset(hs, 0, sizeof(hybrid_handshake_t));
    hs->is_initiator = is_initiator;
    hs->state = HYBRID_STATE_INIT;

    if (p2p_kx_keypair(hs->x25519_pk, hs->x25519_sk) != 0) {
        LOG_ERROR("pqc: Failed to generate X25519 keypair");
        hs->state = HYBRID_STATE_ERROR;
        return -1;
    }

    if (pqc_kem_keypair(hs->kem_pk, hs->kem_sk) != 0) {
        LOG_ERROR("pqc: Failed to generate KEM keypair");
        hs->state = HYBRID_STATE_ERROR;
        return -1;
    }

    hs->state = HYBRID_STATE_KEYS_GENERATED;

    LOG_DEBUG("pqc: Hybrid handshake initialized (initiator=%d, pqc=%s)",
              is_initiator, pqc_is_available() ? "real" : "simulated");
    return 0;
}

/*  Function: hybrid_handshake_cleanup
    Description:
    Securely cleans up a hybrid handshake context by zeroing all secret material.

    Parameters:
    - hs: Pointer to the hybrid_handshake_t context.

    Steps:
    1. Zeros X25519 secret key, KEM secret key, and all shared secrets.
    2. Zeros rx_key and tx_key.
    3. Resets state to INIT.
    4. Logs cleanup.
*/
void hybrid_handshake_cleanup(hybrid_handshake_t* hs) {
    if (!hs) return;

    p2p_memzero(hs->x25519_sk, sizeof(hs->x25519_sk));
    p2p_memzero(hs->kem_sk, sizeof(hs->kem_sk));
    p2p_memzero(hs->x25519_ss, sizeof(hs->x25519_ss));
    p2p_memzero(hs->kem_ss, sizeof(hs->kem_ss));
    p2p_memzero(hs->rx_key, sizeof(hs->rx_key));
    p2p_memzero(hs->tx_key, sizeof(hs->tx_key));

    hs->state = HYBRID_STATE_INIT;

    LOG_TRACE("pqc: Hybrid handshake cleaned up");
}

/*  Function: hybrid_generate_bundle
    Description:
    Generates a hybrid key bundle containing X25519 + KEM public keys, signed with the identity key.

    Parameters:
    - hs: Pointer to the hybrid_handshake_t context.
    - bundle_out: Output key bundle.
    - identity_sk: Ed25519 secret key for signing.
    - identity_pk: Ed25519 public key included in the bundle.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Validates state is at least KEYS_GENERATED.
    2. Copies X25519 and KEM public keys into the bundle.
    3. Signs (x25519_pk || kem_pk) with the identity secret key.
    4. Transitions to BUNDLE_SENT state.
*/
int hybrid_generate_bundle(hybrid_handshake_t* hs,
                           hybrid_key_bundle_t* bundle_out,
                           const uint8_t identity_sk[CRYPTO_SIGN_SK_SIZE],
                           const uint8_t identity_pk[CRYPTO_SIGN_PK_SIZE]) {
    if (!hs || !bundle_out || !identity_sk || !identity_pk) return -1;
    if (hs->state < HYBRID_STATE_KEYS_GENERATED) return -1;

    memset(bundle_out, 0, sizeof(hybrid_key_bundle_t));
    bundle_out->version = HYBRID_HANDSHAKE_VERSION;
    bundle_out->has_pqc = true;

    memcpy(bundle_out->x25519_pk, hs->x25519_pk, CRYPTO_KX_PK_SIZE);
    memcpy(bundle_out->kem_pk, hs->kem_pk, PQC_KEM_PK_SIZE);
    memcpy(bundle_out->identity_pk, identity_pk, CRYPTO_SIGN_PK_SIZE);

    size_t sign_data_len = CRYPTO_KX_PK_SIZE + PQC_KEM_PK_SIZE;
    uint8_t* sign_data = malloc(sign_data_len);
    if (!sign_data) return -1;

    memcpy(sign_data, hs->x25519_pk, CRYPTO_KX_PK_SIZE);
    memcpy(sign_data + CRYPTO_KX_PK_SIZE, hs->kem_pk, PQC_KEM_PK_SIZE);

    size_t sig_len;
    int ret = p2p_sign_create(bundle_out->signature, &sig_len,
                              sign_data, sign_data_len, identity_sk);
    free(sign_data);

    if (ret != 0) {
        LOG_ERROR("pqc: Failed to sign key bundle");
        return -1;
    }

    hs->state = HYBRID_STATE_BUNDLE_SENT;

    LOG_DEBUG("pqc: Key bundle generated (x25519 + KEM + Ed25519 sig)");
    return 0;
}

/*  Function: hybrid_process_bundle
    Description:
    Processes and verifies a peer's hybrid key bundle, then derives the X25519 shared secret.

    Parameters:
    - hs: Pointer to the hybrid_handshake_t context.
    - peer_bundle: Peer's key bundle to process.

    Returns:
    - 0 on success, -1 on failure (invalid signature or key exchange failure).

    Steps:
    1. Reconstructs signed data (x25519_pk || kem_pk).
    2. Verifies the signature using the peer's identity public key.
    3. Stores peer's keys.
    4. Derives X25519 shared secret.
    5. Transitions to BUNDLE_RECEIVED state.
*/
int hybrid_process_bundle(hybrid_handshake_t* hs,
                          const hybrid_key_bundle_t* peer_bundle) {
    if (!hs || !peer_bundle) return -1;

    size_t sign_data_len = CRYPTO_KX_PK_SIZE + PQC_KEM_PK_SIZE;
    uint8_t* sign_data = malloc(sign_data_len);
    if (!sign_data) return -1;

    memcpy(sign_data, peer_bundle->x25519_pk, CRYPTO_KX_PK_SIZE);
    memcpy(sign_data + CRYPTO_KX_PK_SIZE, peer_bundle->kem_pk, PQC_KEM_PK_SIZE);

    int ret = p2p_sign_verify(peer_bundle->signature,
                              sign_data, sign_data_len,
                              peer_bundle->identity_pk);
    free(sign_data);

    if (ret != 0) {
        LOG_ERROR("pqc: Peer key bundle signature INVALID!");
        hs->state = HYBRID_STATE_ERROR;
        return -1;
    }

    memcpy(hs->peer_x25519_pk, peer_bundle->x25519_pk, CRYPTO_KX_PK_SIZE);
    memcpy(hs->peer_kem_pk, peer_bundle->kem_pk, PQC_KEM_PK_SIZE);
    memcpy(hs->peer_identity_pk, peer_bundle->identity_pk, CRYPTO_SIGN_PK_SIZE);

    if (p2p_kx_session_keys(hs->x25519_ss, hs->x25519_ss,
                            hs->x25519_pk, hs->x25519_sk,
                            hs->peer_x25519_pk,
                            hs->is_initiator) != 0) {
        LOG_ERROR("pqc: X25519 key exchange failed");
        hs->state = HYBRID_STATE_ERROR;
        return -1;
    }

    hs->state = HYBRID_STATE_BUNDLE_RECEIVED;

    LOG_DEBUG("pqc: Peer bundle verified and processed");
    return 0;
}

/*  Function: hybrid_encapsulate
    Description:
    Initiator-only: encapsulates a shared secret against the peer's KEM public key.

    Parameters:
    - hs: Pointer to the hybrid_handshake_t context.
    - ct_out: Output buffer for the KEM ciphertext.
    - ct_buf_size: Size of the output buffer.

    Returns:
    - Number of bytes written to ct_out on success, -1 on failure.

    Steps:
    1. Validates that this side is the initiator.
    2. Calls pqc_kem_encapsulate with the peer's KEM public key.
    3. Stores the ciphertext and marks PQC as used.
*/
int hybrid_encapsulate(hybrid_handshake_t* hs,
                       uint8_t* ct_out, size_t ct_buf_size) {
    if (!hs || !ct_out) return -1;
    if (!hs->is_initiator) {
        LOG_ERROR("pqc: Only initiator should encapsulate");
        return -1;
    }
    if (ct_buf_size < PQC_KEM_CT_SIZE) return -1;

    if (pqc_kem_encapsulate(ct_out, hs->kem_ss, hs->peer_kem_pk) != 0) {
        LOG_ERROR("pqc: KEM encapsulation failed");
        hs->state = HYBRID_STATE_ERROR;
        return -1;
    }

    memcpy(hs->kem_ciphertext, ct_out, PQC_KEM_CT_SIZE);
    hs->pqc_used = true;

    LOG_DEBUG("pqc: KEM encapsulated (%d bytes ciphertext)", PQC_KEM_CT_SIZE);
    return PQC_KEM_CT_SIZE;
}

/*  Function: hybrid_decapsulate
    Description:
    Responder-only: decapsulates the shared secret from the initiator's KEM ciphertext.

    Parameters:
    - hs: Pointer to the hybrid_handshake_t context.
    - ct: Input KEM ciphertext.
    - ct_len: Length of the ciphertext.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Validates that this side is the responder.
    2. Calls pqc_kem_decapsulate with our KEM secret key.
    3. Stores the ciphertext and marks PQC as used.
*/
int hybrid_decapsulate(hybrid_handshake_t* hs,
                       const uint8_t* ct, size_t ct_len) {
    if (!hs || !ct) return -1;
    if (hs->is_initiator) {
        LOG_ERROR("pqc: Only responder should decapsulate");
        return -1;
    }
    if (ct_len < PQC_KEM_CT_SIZE) return -1;

    if (pqc_kem_decapsulate(hs->kem_ss, ct, hs->kem_sk) != 0) {
        LOG_ERROR("pqc: KEM decapsulation failed");
        hs->state = HYBRID_STATE_ERROR;
        return -1;
    }

    memcpy(hs->kem_ciphertext, ct, PQC_KEM_CT_SIZE);
    hs->pqc_used = true;

    LOG_DEBUG("pqc: KEM decapsulated successfully");
    return 0;
}

/*  Function: hybrid_derive_keys
    Description:
    Derives final rx and tx session keys from the combined X25519 and KEM shared secrets using HKDF.

    Parameters:
    - hs: Pointer to the hybrid_handshake_t context.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Concatenates x25519_ss and kem_ss into IKM.
    2. Derives rx_key using HKDF with info "hybrid-rx".
    3. Derives tx_key using HKDF with info "hybrid-tx".
    4. Swaps rx/tx for the responder so keys match.
    5. Zeros all intermediate secrets.
    6. Transitions to ESTABLISHED state.
*/
int hybrid_derive_keys(hybrid_handshake_t* hs) {
    if (!hs) return -1;

    size_t ikm_len = CRYPTO_KX_SESSION_SIZE + PQC_KEM_SS_SIZE;
    uint8_t ikm[CRYPTO_KX_SESSION_SIZE + PQC_KEM_SS_SIZE];
    memcpy(ikm, hs->x25519_ss, CRYPTO_KX_SESSION_SIZE);
    memcpy(ikm + CRYPTO_KX_SESSION_SIZE, hs->kem_ss, PQC_KEM_SS_SIZE);

    const uint8_t salt[] = "ENCLAVE_HYBRID_v1";

    const uint8_t info_rx[] = "hybrid-rx";
    crypto_hkdf_sha256(hs->rx_key, HYBRID_SHARED_SECRET_SIZE,
                       ikm, ikm_len,
                       salt, sizeof(salt) - 1,
                       info_rx, sizeof(info_rx) - 1);

    const uint8_t info_tx[] = "hybrid-tx";
    crypto_hkdf_sha256(hs->tx_key, HYBRID_SHARED_SECRET_SIZE,
                       ikm, ikm_len,
                       salt, sizeof(salt) - 1,
                       info_tx, sizeof(info_tx) - 1);

    if (!hs->is_initiator) {
        uint8_t tmp[HYBRID_SHARED_SECRET_SIZE];
        memcpy(tmp, hs->rx_key, HYBRID_SHARED_SECRET_SIZE);
        memcpy(hs->rx_key, hs->tx_key, HYBRID_SHARED_SECRET_SIZE);
        memcpy(hs->tx_key, tmp, HYBRID_SHARED_SECRET_SIZE);
        p2p_memzero(tmp, HYBRID_SHARED_SECRET_SIZE);
    }

    p2p_memzero(ikm, ikm_len);
    p2p_memzero(hs->x25519_ss, sizeof(hs->x25519_ss));
    p2p_memzero(hs->kem_ss, sizeof(hs->kem_ss));

    hs->state = HYBRID_STATE_ESTABLISHED;

    LOG_INFO("pqc: Hybrid session keys derived (pqc_used=%d, kem=%s)",
             hs->pqc_used, pqc_kem_name());
    return 0;
}