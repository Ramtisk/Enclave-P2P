#include "memory.h"

#ifdef USE_LIBSODIUM
#include <sodium.h>
#endif

/*  Function: p2p_memzero
    Description:
    Securely zeros a memory buffer, preventing compiler optimization from removing the operation.

    Parameters:
    - buf: Pointer to the memory to zero.
    - len: Number of bytes to zero.

    Steps:
    1. Returns immediately if buf is NULL or len is 0.
    2. If USE_LIBSODIUM, delegates to sodium_memzero().
    3. Otherwise, uses a volatile pointer to write zeros byte by byte.
*/
void p2p_memzero(void* buf, size_t len) {
    if (!buf || len == 0) return;
#ifdef USE_LIBSODIUM
    sodium_memzero(buf, len);
#else
    volatile uint8_t* p = (volatile uint8_t*)buf;
    while (len--) *p++ = 0;
#endif
}

/*  Function: p2p_memcmp_ct
    Description:
    Compares two buffers in constant time to prevent timing side-channel attacks.

    Parameters:
    - a: First buffer.
    - b: Second buffer.
    - len: Number of bytes to compare.

    Returns:
    - 0 if equal, -1 if different or if either pointer is NULL.

    Steps:
    1. Returns -1 if either pointer is NULL.
    2. If USE_LIBSODIUM, delegates to sodium_memcmp().
    3. Otherwise, XORs all bytes and checks if any differ.
*/
int p2p_memcmp_ct(const void* a, const void* b, size_t len) {
    if (!a || !b) return -1;
#ifdef USE_LIBSODIUM
    return sodium_memcmp(a, b, len);
#else
    const uint8_t* pa = (const uint8_t*)a;
    const uint8_t* pb = (const uint8_t*)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= pa[i] ^ pb[i];
    }
    return diff != 0 ? -1 : 0;
#endif
}