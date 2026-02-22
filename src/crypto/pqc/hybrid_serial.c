#include "hybrid_serial.h"
#include "../signing.h"
#include "../../common/logging.h"

#include <string.h>

/*  Function: hybrid_bundle_serialize
    Description:
    Serializes a hybrid key bundle into a byte buffer for network transmission.

    Parameters:
    - bundle: Input key bundle to serialize.
    - buf: Output buffer.
    - buf_size: Size of the output buffer.
    - out_len: Output pointer for the number of bytes written.

    Returns:
    - 0 on success, -1 if buffer is too small or input is NULL.

    Steps:
    1. Computes the total size (header + optional kem_pk + identity_pk + signature).
    2. Writes the header (version, flags, x25519_pk, kem_pk_len).
    3. Writes the KEM public key if present.
    4. Writes the identity public key and signature.
    5. Sets out_len to the number of bytes written.
*/
int hybrid_bundle_serialize(const hybrid_key_bundle_t* bundle,
                            uint8_t* buf, size_t buf_size, size_t* out_len) {
    if (!bundle || !buf) return -1;

    uint16_t kem_len = bundle->has_pqc ? PQC_KEM_PK_SIZE : 0;
    size_t total = sizeof(hybrid_bundle_header_t) + kem_len +
                   CRYPTO_SIGN_PK_SIZE + CRYPTO_SIGN_SIZE;

    if (buf_size < total) return -1;

    hybrid_bundle_header_t* hdr = (hybrid_bundle_header_t*)buf;
    hdr->version = bundle->version;
    hdr->flags = bundle->has_pqc ? HYBRID_FLAG_HAS_PQC : 0;
    memcpy(hdr->x25519_pk, bundle->x25519_pk, 32);
    hdr->kem_pk_len = kem_len;

    uint8_t* ptr = buf + sizeof(hybrid_bundle_header_t);

    if (kem_len > 0) {
        memcpy(ptr, bundle->kem_pk, kem_len);
        ptr += kem_len;
    }

    memcpy(ptr, bundle->identity_pk, CRYPTO_SIGN_PK_SIZE);
    ptr += CRYPTO_SIGN_PK_SIZE;

    memcpy(ptr, bundle->signature, CRYPTO_SIGN_SIZE);
    ptr += CRYPTO_SIGN_SIZE;

    if (out_len) *out_len = (size_t)(ptr - buf);
    return 0;
}

/*  Function: hybrid_bundle_deserialize
    Description:
    Deserializes a hybrid key bundle from a byte buffer received over the network.

    Parameters:
    - bundle: Output key bundle structure.
    - buf: Input buffer.
    - buf_len: Length of the input buffer.

    Returns:
    - 0 on success, -1 on failure (buffer too small, invalid data).

    Steps:
    1. Validates minimum buffer size for the header.
    2. Reads version, flags, and x25519_pk from the header.
    3. Reads the KEM public key if present and validates length.
    4. Reads the identity public key and signature.
*/
int hybrid_bundle_deserialize(hybrid_key_bundle_t* bundle,
                              const uint8_t* buf, size_t buf_len) {
    if (!bundle || !buf) return -1;
    if (buf_len < sizeof(hybrid_bundle_header_t)) return -1;

    const hybrid_bundle_header_t* hdr = (const hybrid_bundle_header_t*)buf;

    memset(bundle, 0, sizeof(hybrid_key_bundle_t));
    bundle->version = hdr->version;
    bundle->has_pqc = (hdr->flags & HYBRID_FLAG_HAS_PQC) != 0;
    memcpy(bundle->x25519_pk, hdr->x25519_pk, 32);

    const uint8_t* ptr = buf + sizeof(hybrid_bundle_header_t);
    size_t remaining = buf_len - sizeof(hybrid_bundle_header_t);

    uint16_t kem_len = hdr->kem_pk_len;
    if (kem_len > 0) {
        if (remaining < kem_len) return -1;
        if (kem_len > PQC_KEM_PK_SIZE) return -1;
        memcpy(bundle->kem_pk, ptr, kem_len);
        ptr += kem_len;
        remaining -= kem_len;
    }

    if (remaining < CRYPTO_SIGN_PK_SIZE + CRYPTO_SIGN_SIZE) return -1;

    memcpy(bundle->identity_pk, ptr, CRYPTO_SIGN_PK_SIZE);
    ptr += CRYPTO_SIGN_PK_SIZE;

    memcpy(bundle->signature, ptr, CRYPTO_SIGN_SIZE);

    return 0;
}