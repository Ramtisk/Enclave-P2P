#ifndef P2P_CRYPTO_RANDOM_H
#define P2P_CRYPTO_RANDOM_H

#include <stdint.h>
#include <stddef.h>

/*  ============================================
    RANDOM BYTES

    Note: Generates cryptographically secure random bytes.
    Uses libsodium if available, otherwise falls back to /dev/urandom.
    ============================================ */
void p2p_random_bytes(uint8_t* buf, size_t len);

#endif