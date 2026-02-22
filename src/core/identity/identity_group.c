#define _POSIX_C_SOURCE 200809L
#include "identity_group.h"
#include "identity_peer.h"
#include "identity_helpers.h"
#include "../../crypto/classic.h"
#include "../../crypto/hashing.h"
#include "../../common/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void sha256_hash(const uint8_t *data, size_t len, uint8_t *hash_out);

/*  Function: identity_create_group_ephemeral
    Description:
    Creates a new ephemeral identity for a group, generating Ed25519 and X25519 keypairs,
    deriving a fingerprint, and creating a binding proof signed by the long-term key.

    Parameters:
    - long_term: Pointer to the long-term peer identity.
    - gid: Pointer to the group_identity_t structure to initialize.
    - group_id_str: The group ID string.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Validates input parameters.
    2. Clears the group identity structure and sets the group ID.
    3. Generates ephemeral Ed25519 and X25519 keypairs.
    4. Derives fingerprint and ephemeral ID from the ephemeral public key.
    5. Creates a binding proof by signing (ephemeral_sign_pk || ephemeral_kx_pk || group_id) with the long-term key.
    6. Sets creation timestamp and marks identity as active.
    7. Logs the creation event.
*/
int identity_create_group_ephemeral(peer_identity_t *long_term,
                                    group_identity_t *gid,
                                    const char *group_id_str)
{
    if (!long_term || !long_term->initialized || !gid || !group_id_str)
        return -1;

    memset(gid, 0, sizeof(group_identity_t));
    strncpy(gid->group_id, group_id_str, MAX_ID_LENGTH - 1);

    if (p2p_sign_keypair(gid->sign_pk, gid->sign_sk) != 0)
    {
        LOG_ERROR("identity: Failed to generate ephemeral sign keypair");
        return -1;
    }

    if (p2p_kx_keypair(gid->kx_pk, gid->kx_sk) != 0)
    {
        LOG_ERROR("identity: Failed to generate ephemeral KX keypair");
        return -1;
    }

    uint8_t hash[32];
    sha256_hash(gid->sign_pk, CRYPTO_SIGN_PK_SIZE, hash);
    memcpy(gid->fingerprint, hash, IDENTITY_FINGERPRINT_SIZE);

    char hex[17];
    identity_bytes_to_hex(gid->fingerprint, 8, hex, sizeof(hex));
    snprintf(gid->ephemeral_id, MAX_ID_LENGTH, "eph_%s", hex);

    size_t bind_data_len = CRYPTO_SIGN_PK_SIZE + CRYPTO_KX_PK_SIZE + strlen(group_id_str);
    uint8_t *bind_data = malloc(bind_data_len);
    if (!bind_data)
        return -1;

    memcpy(bind_data, gid->sign_pk, CRYPTO_SIGN_PK_SIZE);
    memcpy(bind_data + CRYPTO_SIGN_PK_SIZE, gid->kx_pk, CRYPTO_KX_PK_SIZE);
    memcpy(bind_data + CRYPTO_SIGN_PK_SIZE + CRYPTO_KX_PK_SIZE,
           group_id_str, strlen(group_id_str));

    size_t sig_len;
    int ret = identity_sign(long_term, gid->binding_sig, &sig_len,
                            bind_data, bind_data_len);
    free(bind_data);

    if (ret != 0)
    {
        LOG_ERROR("identity: Failed to create binding proof");
        return -1;
    }

    gid->created_at = identity_get_timestamp_ms();
    gid->active = true;

    LOG_INFO("identity: Created group ephemeral for '%s'", group_id_str);
    LOG_INFO("identity:   Ephemeral ID: %s", gid->ephemeral_id);

    return 0;
}

/*  Function: identity_verify_binding
    Description:
    Verifies that a group ephemeral identity was created by the owner of the given long-term public key.

    Parameters:
    - long_term_pk: Long-term public key of the claimed owner.
    - ephemeral: Pointer to the group_identity_t to verify.

    Returns:
    - 0 if the binding proof is valid, -1 on failure.

    Steps:
    1. Reconstructs the binding data (ephemeral_sign_pk || ephemeral_kx_pk || group_id).
    2. Verifies the binding signature using the long-term public key.
    3. Logs the result.
*/
int identity_verify_binding(const uint8_t long_term_pk[CRYPTO_SIGN_PK_SIZE],
                            const group_identity_t *ephemeral)
{
    if (!long_term_pk || !ephemeral)
        return -1;

    size_t bind_data_len = CRYPTO_SIGN_PK_SIZE + CRYPTO_KX_PK_SIZE +
                           strlen(ephemeral->group_id);
    uint8_t *bind_data = malloc(bind_data_len);
    if (!bind_data)
        return -1;

    memcpy(bind_data, ephemeral->sign_pk, CRYPTO_SIGN_PK_SIZE);
    memcpy(bind_data + CRYPTO_SIGN_PK_SIZE, ephemeral->kx_pk, CRYPTO_KX_PK_SIZE);
    memcpy(bind_data + CRYPTO_SIGN_PK_SIZE + CRYPTO_KX_PK_SIZE,
           ephemeral->group_id, strlen(ephemeral->group_id));

    int ret = identity_verify(long_term_pk, ephemeral->binding_sig,
                              bind_data, bind_data_len);
    free(bind_data);

    if (ret != 0)
    {
        LOG_WARN("identity: Binding proof verification FAILED");
        return -1;
    }

    LOG_DEBUG("identity: Binding proof verified for group %s", ephemeral->group_id);
    return 0;
}

/*  Function: identity_group_sign
    Description:
    Signs data using the ephemeral Ed25519 secret key for a group.

    Parameters:
    - gid: Pointer to the group_identity_t structure.
    - sig: Output buffer for the signature.
    - sig_len: Output pointer for the signature length.
    - data: Data to sign.
    - data_len: Length of the data.

    Returns:
    - 0 on success, -1 on failure or if the identity is not active.
*/
int identity_group_sign(const group_identity_t *gid,
                        uint8_t *sig, size_t *sig_len,
                        const uint8_t *data, size_t data_len)
{
    if (!gid || !gid->active || !sig || !data)
        return -1;
    return p2p_sign_create(sig, sig_len, data, data_len, gid->sign_sk);
}

/*  Function: identity_group_verify
    Description:
    Verifies a signature using a group ephemeral public key.

    Parameters:
    - ephemeral_pk: Ephemeral public key of the signer.
    - sig: Signature to verify.
    - data: Original data that was signed.
    - data_len: Length of the data.

    Returns:
    - 0 if the signature is valid, -1 on failure.
*/
int identity_group_verify(const uint8_t ephemeral_pk[CRYPTO_SIGN_PK_SIZE],
                          const uint8_t *sig,
                          const uint8_t *data, size_t data_len)
{
    return identity_verify(ephemeral_pk, sig, data, data_len);
}