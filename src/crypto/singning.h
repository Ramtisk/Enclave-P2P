#ifndef P2P_CRYPTO_SIGNING_H
#define P2P_CRYPTO_SIGNING_H

#include <stdint.h>
#include <stddef.h>

/*  ============================================
    ED25519 SIGNATURE CONSTANTS

    Note: Sizes for Ed25519 digital signature keys and signatures.
    ============================================ */
#define CRYPTO_SIGN_PK_SIZE    32
#define CRYPTO_SIGN_SK_SIZE    64
#define CRYPTO_SIGN_SIZE       64

/*  ============================================
    ED25519 SIGNATURES API

    Note: Functions for generating Ed25519 keypairs, creating detached signatures,
    and verifying detached signatures.
    Uses libsodium if available, otherwise a software stub (NOT secure for production).
    ============================================ */
int p2p_sign_keypair(uint8_t pk[CRYPTO_SIGN_PK_SIZE],
                     uint8_t sk[CRYPTO_SIGN_SK_SIZE]);

int p2p_sign_create(uint8_t* sig, size_t* sig_len,
                    const uint8_t* msg, size_t msg_len,
                    const uint8_t sk[CRYPTO_SIGN_SK_SIZE]);

int p2p_sign_verify(const uint8_t* sig,
                    const uint8_t* msg, size_t msg_len,
                    const uint8_t pk[CRYPTO_SIGN_PK_SIZE]);

#endif