#ifndef P2P_IDENTITY_ZKP_H
#define P2P_IDENTITY_ZKP_H

#include "identity_types.h"

/*  ============================================
    ZERO-KNOWLEDGE PROOF API

    Note: Functions for creating and verifying Schnorr-like
    zero-knowledge proofs using non-interactive Fiat-Shamir heuristic.
    Proves knowledge of a secret key without revealing it.
    ============================================ */
int zkp_create(zkp_proof_t *proof,
               const uint8_t pk[CRYPTO_SIGN_PK_SIZE],
               const uint8_t sk[CRYPTO_SIGN_SK_SIZE],
               const uint8_t *context, size_t context_len);
int zkp_verify(const zkp_proof_t *proof,
               const uint8_t pk[CRYPTO_SIGN_PK_SIZE],
               const uint8_t *context, size_t context_len);

#endif