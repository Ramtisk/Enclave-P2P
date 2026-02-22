#include "crypto_init.h"
#include "../common/logging.h"

#include <stdio.h>
#include <time.h>

#ifdef USE_LIBSODIUM
#include <sodium.h>
#endif

/*  Function: p2p_crypto_init
    Description:
    Initializes the cryptographic backend for the application.

    Steps:
    1. If USE_LIBSODIUM is defined, calls sodium_init() and logs version info.
    2. If not, seeds the fallback PRNG with current time and logs a warning.
    3. Returns 0 on success, -1 on failure.
*/
int p2p_crypto_init(void) {
#ifdef USE_LIBSODIUM
    if (sodium_init() < 0) {
        LOG_FATAL("crypto: libsodium initialization failed");
        return -1;
    }
    LOG_INFO("crypto: libsodium %s initialized", sodium_version_string());
    LOG_INFO("crypto:   AEAD: ChaCha20-Poly1305-IETF (key=32, nonce=12, tag=16)");
    LOG_INFO("crypto:   Sign: Ed25519 (pk=32, sk=64, sig=64)");
    LOG_INFO("crypto:   KX:   X25519 (pk=32, sk=32, session=32)");
#else
    LOG_WARN("crypto: Running WITHOUT libsodium — software fallback only!");
    LOG_WARN("crypto: DO NOT use in production!");
    srand((unsigned)time(NULL));
#endif
    return 0;
}