#define _POSIX_C_SOURCE 200809L
#include "identity_zkp.h"
#include "../../crypto/classic.h"
#include "../../crypto/hashing.h"
#include "../../common/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void sha256_hash(const uint8_t *data, size_t len, uint8_t *hash_out);

/*  Function: zkp_create
    Description:
    Creates a non-interactive Schnorr-like zero-knowledge proof
    proving knowledge of the secret key for a given public key.

    Parameters:
    - proof: Pointer to the zkp_proof_t structure to fill.
    - pk: Public key to prove knowledge of.
    - sk: Secret key (the knowledge being proved).
    - context: Optional context bytes for domain separation.
    - context_len: Length of context.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Clears the proof structure.
    2. Generates a random nonce r.
    3. Computes commitment R = Hash(r) (simulated r*G).
    4. Computes challenge c = Hash(pk || R || context).
    5. Computes response s = Sign_sk(R || c) as a proxy for r + c*sk.
    6. Zeros the nonce from memory.
    7. Logs the result.
*/
int zkp_create(zkp_proof_t *proof,
               const uint8_t pk[CRYPTO_SIGN_PK_SIZE],
               const uint8_t sk[CRYPTO_SIGN_SK_SIZE],
               const uint8_t *context, size_t context_len)
{
    if (!proof || !pk || !sk)
        return -1;

    memset(proof, 0, sizeof(zkp_proof_t));

    uint8_t r[64];
    p2p_random_bytes(r, sizeof(r));

    sha256_hash(r, sizeof(r), proof->commitment);

    size_t challenge_input_len = CRYPTO_SIGN_PK_SIZE + CRYPTO_SIGN_PK_SIZE +
                                 (context ? context_len : 0);
    uint8_t *challenge_input = malloc(challenge_input_len);
    if (!challenge_input)
    {
        p2p_memzero(r, sizeof(r));
        return -1;
    }

    memcpy(challenge_input, pk, CRYPTO_SIGN_PK_SIZE);
    memcpy(challenge_input + CRYPTO_SIGN_PK_SIZE, proof->commitment, CRYPTO_SIGN_PK_SIZE);
    if (context && context_len > 0)
    {
        memcpy(challenge_input + CRYPTO_SIGN_PK_SIZE * 2, context, context_len);
    }

    sha256_hash(challenge_input, challenge_input_len, proof->challenge);
    free(challenge_input);

    uint8_t response_input[CRYPTO_SIGN_PK_SIZE + ZKP_CHALLENGE_SIZE];
    memcpy(response_input, proof->commitment, CRYPTO_SIGN_PK_SIZE);
    memcpy(response_input + CRYPTO_SIGN_PK_SIZE, proof->challenge, ZKP_CHALLENGE_SIZE);

    size_t sig_len;
    int ret = p2p_sign_create(proof->response, &sig_len,
                              response_input, sizeof(response_input), sk);

    p2p_memzero(r, sizeof(r));

    if (ret != 0)
    {
        LOG_ERROR("identity: ZKP creation failed");
        return -1;
    }

    LOG_DEBUG("identity: ZKP created for public key");
    return 0;
}

/*  Function: zkp_verify
    Description:
    Verifies a non-interactive Schnorr-like zero-knowledge proof.

    Parameters:
    - proof: Pointer to the zkp_proof_t structure to verify.
    - pk: Public key the proof claims knowledge of.
    - context: Optional context bytes for domain separation.
    - context_len: Length of context.

    Returns:
    - 0 if the proof is valid, -1 on failure.

    Steps:
    1. Recomputes the challenge c = Hash(pk || R || context).
    2. Compares the recomputed challenge with the proof's challenge (constant-time).
    3. Verifies the response signature using the public key.
    4. Logs the result.
*/
int zkp_verify(const zkp_proof_t *proof,
               const uint8_t pk[CRYPTO_SIGN_PK_SIZE],
               const uint8_t *context, size_t context_len)
{
    if (!proof || !pk)
        return -1;

    size_t challenge_input_len = CRYPTO_SIGN_PK_SIZE + CRYPTO_SIGN_PK_SIZE +
                                 (context ? context_len : 0);
    uint8_t *challenge_input = malloc(challenge_input_len);
    if (!challenge_input)
        return -1;

    memcpy(challenge_input, pk, CRYPTO_SIGN_PK_SIZE);
    memcpy(challenge_input + CRYPTO_SIGN_PK_SIZE,
           proof->commitment, CRYPTO_SIGN_PK_SIZE);
    if (context && context_len > 0)
    {
        memcpy(challenge_input + CRYPTO_SIGN_PK_SIZE * 2, context, context_len);
    }

    uint8_t expected_challenge[32];
    sha256_hash(challenge_input, challenge_input_len, expected_challenge);
    free(challenge_input);

    if (p2p_memcmp_ct(expected_challenge, proof->challenge, ZKP_CHALLENGE_SIZE) != 0)
    {
        LOG_WARN("identity: ZKP challenge mismatch");
        return -1;
    }

    uint8_t response_input[CRYPTO_SIGN_PK_SIZE + ZKP_CHALLENGE_SIZE];
    memcpy(response_input, proof->commitment, CRYPTO_SIGN_PK_SIZE);
    memcpy(response_input + CRYPTO_SIGN_PK_SIZE, proof->challenge, ZKP_CHALLENGE_SIZE);

    if (p2p_sign_verify(proof->response, response_input,
                        sizeof(response_input), pk) != 0)
    {
        LOG_WARN("identity: ZKP response verification failed");
        return -1;
    }

    LOG_DEBUG("identity: ZKP verified successfully");
    return 0;
}