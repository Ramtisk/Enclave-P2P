#define _POSIX_C_SOURCE 200809L
#include "identity_peer.h"
#include "identity_helpers.h"
#include "../../crypto/classic.h"
#include "../../crypto/hashing.h"
#include "../../common/logging.h"

#include <stdio.h>
#include <string.h>

extern void sha256_hash(const uint8_t *data, size_t len, uint8_t *hash_out);

/*  Function: identity_generate
    Description:
    Generates a new long-term peer identity with Ed25519 keypair.

    Parameters:
    - id: Pointer to the peer_identity_t structure to initialize.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Clears the structure with memset.
    2. Generates an Ed25519 signing keypair.
    3. Sets creation timestamp and version.
    4. Marks the identity as initialized.
    5. Derives the peer ID and fingerprint.
    6. Logs the new identity details.
*/
int identity_generate(peer_identity_t *id)
{
    if (!id)
        return -1;

    memset(id, 0, sizeof(peer_identity_t));

    if (p2p_sign_keypair(id->sign_pk, id->sign_sk) != 0)
    {
        LOG_ERROR("identity: Failed to generate Ed25519 keypair");
        return -1;
    }

    id->created_at = identity_get_timestamp_ms();
    id->version = IDENTITY_VERSION;
    id->initialized = true;

    identity_derive_id(id);

    char fp_hex[IDENTITY_FINGERPRINT_SIZE * 2 + 1];
    identity_fingerprint_hex(id, fp_hex, sizeof(fp_hex));

    LOG_INFO("identity: Generated new identity");
    LOG_INFO("identity:   Peer ID: %s", id->peer_id);
    LOG_INFO("identity:   Fingerprint: %s", fp_hex);

    return 0;
}

/*  Function: identity_derive_id
    Description:
    Derives the peer ID and fingerprint from the public key.

    Parameters:
    - id: Pointer to the peer_identity_t structure.

    Steps:
    1. Computes SHA-256 hash of the public key.
    2. Copies the first 16 bytes as the fingerprint.
    3. Formats the peer ID as "peer_<hex fingerprint>".
*/
void identity_derive_id(peer_identity_t *id)
{
    if (!id)
        return;

    uint8_t hash[32];
    sha256_hash(id->sign_pk, CRYPTO_SIGN_PK_SIZE, hash);
    memcpy(id->fingerprint, hash, IDENTITY_FINGERPRINT_SIZE);

    char hex[17];
    identity_bytes_to_hex(id->fingerprint, 8, hex, sizeof(hex));
    snprintf(id->peer_id, MAX_ID_LENGTH, "peer_%s", hex);
}

/*  Function: identity_sign
    Description:
    Signs data using the long-term Ed25519 secret key.

    Parameters:
    - id: Pointer to the peer_identity_t structure.
    - sig: Output buffer for the signature.
    - sig_len: Output pointer for the signature length.
    - data: Data to sign.
    - data_len: Length of the data.

    Returns:
    - 0 on success, -1 on failure or invalid parameters.
*/
int identity_sign(const peer_identity_t *id,
                  uint8_t *sig, size_t *sig_len,
                  const uint8_t *data, size_t data_len)
{
    if (!id || !id->initialized || !sig || !data)
        return -1;
    return p2p_sign_create(sig, sig_len, data, data_len, id->sign_sk);
}

/*  Function: identity_verify
    Description:
    Verifies an Ed25519 signature against a public key.

    Parameters:
    - pk: Public key of the signer.
    - sig: Signature to verify.
    - data: Original data that was signed.
    - data_len: Length of the data.

    Returns:
    - 0 if the signature is valid, -1 on failure.
*/
int identity_verify(const uint8_t pk[CRYPTO_SIGN_PK_SIZE],
                    const uint8_t *sig,
                    const uint8_t *data, size_t data_len)
{
    if (!pk || !sig || !data)
        return -1;
    return p2p_sign_verify(sig, data, data_len, pk);
}

/*  Function: identity_fingerprint_hex
    Description:
    Returns the fingerprint of a peer identity as a hex string.

    Parameters:
    - id: Pointer to the peer_identity_t structure.
    - hex_out: Output buffer for the hex string.
    - hex_len: Size of the output buffer.
*/
void identity_fingerprint_hex(const peer_identity_t *id,
                              char *hex_out, size_t hex_len)
{
    if (!id || !hex_out)
        return;
    identity_bytes_to_hex(id->fingerprint, IDENTITY_FINGERPRINT_SIZE, hex_out, hex_len);
}