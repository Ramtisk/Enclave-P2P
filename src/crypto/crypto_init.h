#ifndef P2P_CRYPTO_INIT_H
#define P2P_CRYPTO_INIT_H

/*  ============================================
    CRYPTO INITIALIZATION

    Note: Initializes the cryptographic backend.
    If USE_LIBSODIUM is defined, initializes libsodium.
    Otherwise, seeds the fallback PRNG.
    Must be called before any other crypto function.
    ============================================ */
int p2p_crypto_init(void);

#endif