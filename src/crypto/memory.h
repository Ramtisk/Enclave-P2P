#ifndef P2P_CRYPTO_MEMORY_H
#define P2P_CRYPTO_MEMORY_H

#include <stdint.h>
#include <stddef.h>

/*  ============================================
    SECURE MEMORY UTILITIES

    Note: Functions for securely zeroing memory and constant-time comparison.
    - p2p_memzero: Zeros memory in a way that the compiler cannot optimize away.
    - p2p_memcmp_ct: Compares two buffers in constant time to prevent timing attacks.
    ============================================ */
void p2p_memzero(void* buf, size_t len);
int  p2p_memcmp_ct(const void* a, const void* b, size_t len);

#endif