#ifndef P2P_CRYPTO_KX_H
#define P2P_CRYPTO_KX_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*  ============================================
    X25519 KEY EXCHANGE CONSTANTS

    Note: Sizes for X25519 Diffie-Hellman key exchange.
    ============================================ */
#define CRYPTO_KX_PK_SIZE      32
#define CRYPTO_KX_SK_SIZE      32
#define CRYPTO_KX_SESSION_SIZE 32

/*  ============================================
    X25519 KEY EXCHANGE API

    Note: Functions for generating X25519 keypairs and deriving session keys.
    Uses libsodium if available, otherwise a software fallback (NOT secure for production).
    ============================================ */
int p2p_kx_keypair(uint8_t pk[CRYPTO_KX_PK_SIZE],
                   uint8_t sk[CRYPTO_KX_SK_SIZE]);

int p2p_kx_session_keys(uint8_t rx_key[CRYPTO_KX_SESSION_SIZE],
                        uint8_t tx_key[CRYPTO_KX_SESSION_SIZE],
                        const uint8_t our_pk[CRYPTO_KX_PK_SIZE],
                        const uint8_t our_sk[CRYPTO_KX_SK_SIZE],
                        const uint8_t their_pk[CRYPTO_KX_PK_SIZE],
                        bool is_client);

#endif