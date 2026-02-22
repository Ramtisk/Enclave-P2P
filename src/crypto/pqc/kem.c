#include "kem.h"
#include "../random.h"
#include "../memory.h"
#include "../hashing.h"
#include "../../common/logging.h"

#include <stdio.h>
#include <string.h>

/*  Function: pqc_kem_keypair
    Description:
    Generates a KEM keypair for post-quantum key encapsulation.

    Parameters:
    - pk: Output buffer for the public key.
    - sk: Output buffer for the secret key.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. If PQC_KEM_AVAILABLE, delegates to crypto_kem_keypair().
    2. Otherwise, generates random bytes and stores pk inside sk for simulated decapsulation.
    3. Logs a warning if using simulated KEM.
*/
int pqc_kem_keypair(uint8_t pk[PQC_KEM_PK_SIZE],
                    uint8_t sk[PQC_KEM_SK_SIZE]) {
    if (!pk || !sk) return -1;

#if PQC_KEM_AVAILABLE
    return crypto_kem_keypair(pk, sk);
#else
    LOG_WARN("pqc: Using simulated KEM — not post-quantum secure");
    p2p_random_bytes(pk, PQC_KEM_PK_SIZE);
    p2p_random_bytes(sk, PQC_KEM_SK_SIZE);
    memcpy(sk, pk, PQC_KEM_PK_SIZE < PQC_KEM_SK_SIZE ? PQC_KEM_PK_SIZE : PQC_KEM_SK_SIZE);
    return 0;
#endif
}

/*  Function: pqc_kem_encapsulate
    Description:
    Encapsulates a shared secret against a KEM public key, producing a ciphertext.

    Parameters:
    - ct: Output ciphertext buffer.
    - ss: Output shared secret buffer.
    - pk: Peer's KEM public key.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. If PQC_KEM_AVAILABLE, delegates to crypto_kem_enc().
    2. Otherwise, generates random shared secret, computes ct = hash(pk || ss) || XOR encoding || padding.
*/
int pqc_kem_encapsulate(uint8_t ct[PQC_KEM_CT_SIZE],
                        uint8_t ss[PQC_KEM_SS_SIZE],
                        const uint8_t pk[PQC_KEM_PK_SIZE]) {
    if (!ct || !ss || !pk) return -1;

#if PQC_KEM_AVAILABLE
    return crypto_kem_enc(ct, ss, pk);
#else
    p2p_random_bytes(ss, PQC_KEM_SS_SIZE);

    uint8_t hash_input[PQC_KEM_PK_SIZE + PQC_KEM_SS_SIZE];
    memcpy(hash_input, pk, PQC_KEM_PK_SIZE);
    memcpy(hash_input + PQC_KEM_PK_SIZE, ss, PQC_KEM_SS_SIZE);

    sha256_hash(hash_input, sizeof(hash_input), ct);

    for (int i = 0; i < PQC_KEM_SS_SIZE; i++) {
        ct[32 + i] = ss[i] ^ pk[i % PQC_KEM_PK_SIZE];
    }

    if (PQC_KEM_CT_SIZE > 64) {
        p2p_random_bytes(ct + 64, PQC_KEM_CT_SIZE - 64);
    }

    return 0;
#endif
}

/*  Function: pqc_kem_decapsulate
    Description:
    Decapsulates a shared secret from a ciphertext using the KEM secret key.

    Parameters:
    - ss: Output shared secret buffer.
    - ct: Input ciphertext.
    - sk: KEM secret key.

    Returns:
    - 0 on success, -1 on failure (hash mismatch in simulated mode).

    Steps:
    1. If PQC_KEM_AVAILABLE, delegates to crypto_kem_dec().
    2. Otherwise, recovers ss from ct using XOR with pk (stored in sk).
    3. Recomputes hash and verifies integrity.
*/
int pqc_kem_decapsulate(uint8_t ss[PQC_KEM_SS_SIZE],
                        const uint8_t ct[PQC_KEM_CT_SIZE],
                        const uint8_t sk[PQC_KEM_SK_SIZE]) {
    if (!ss || !ct || !sk) return -1;

#if PQC_KEM_AVAILABLE
    return crypto_kem_dec(ss, ct, sk);
#else
    const uint8_t* pk = sk;

    for (int i = 0; i < PQC_KEM_SS_SIZE; i++) {
        ss[i] = ct[32 + i] ^ pk[i % PQC_KEM_PK_SIZE];
    }

    uint8_t hash_input[PQC_KEM_PK_SIZE + PQC_KEM_SS_SIZE];
    memcpy(hash_input, pk, PQC_KEM_PK_SIZE);
    memcpy(hash_input + PQC_KEM_PK_SIZE, ss, PQC_KEM_SS_SIZE);

    uint8_t expected_hash[32];
    sha256_hash(hash_input, sizeof(hash_input), expected_hash);

    if (p2p_memcmp_ct(expected_hash, ct, 32) != 0) {
        LOG_WARN("pqc: Simulated KEM decapsulation failed — hash mismatch");
        p2p_memzero(ss, PQC_KEM_SS_SIZE);
        return -1;
    }

    return 0;
#endif
}

/*  Function: pqc_is_available
    Description:
    Returns whether real post-quantum KEM is available at compile time.

    Returns:
    - true if PQC_KEM_AVAILABLE is 1, false otherwise.
*/
bool pqc_is_available(void) {
#if PQC_KEM_AVAILABLE
    return true;
#else
    return false;
#endif
}

/*  Function: pqc_kem_name
    Description:
    Returns a string describing the KEM algorithm in use.

    Returns:
    - PQC_KEM_NAME constant string.
*/
const char* pqc_kem_name(void) {
    return PQC_KEM_NAME;
}