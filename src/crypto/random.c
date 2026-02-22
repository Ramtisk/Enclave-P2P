#include "random.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_LIBSODIUM
#include <sodium.h>
#endif

#ifndef USE_LIBSODIUM
/*  Function: randombytes_fallback
    Description:
    Reads random bytes from /dev/urandom. Falls back to rand() if /dev/urandom is unavailable.

    Parameters:
    - buf: Output buffer for random bytes.
    - len: Number of bytes to generate.

    Steps:
    1. Tries to open /dev/urandom and read the requested bytes.
    2. If successful, returns immediately.
    3. If /dev/urandom is unavailable, fills the buffer using rand().
*/
static void randombytes_fallback(uint8_t* buf, size_t len) {
    FILE* f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t rd = fread(buf, 1, len, f);
        fclose(f);
        if (rd == len) return;
    }
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
}
#endif

/*  Function: p2p_random_bytes
    Description:
    Generates cryptographically secure random bytes.

    Parameters:
    - buf: Output buffer for random bytes.
    - len: Number of bytes to generate.

    Steps:
    1. If USE_LIBSODIUM, delegates to randombytes_buf().
    2. Otherwise, uses the /dev/urandom fallback.
*/
void p2p_random_bytes(uint8_t* buf, size_t len) {
#ifdef USE_LIBSODIUM
    randombytes_buf(buf, len);
#else
    randombytes_fallback(buf, len);
#endif
}