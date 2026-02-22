#include "kx.h"
#include "random.h"
#include "memory.h"
#include "../common/logging.h"

#include <string.h>

#ifdef USE_LIBSODIUM
#include <sodium.h>
#endif

/*  Function: p2p_kx_keypair
    Description:
    Generates an X25519 key exchange keypair.

    Parameters:
    - pk: Output buffer for the 32-byte public key.
    - sk: Output buffer for the 32-byte secret key.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Validates pointers.
    2. If USE_LIBSODIUM, delegates to crypto_kx_keypair().
    3. Otherwise, fills both keys with random bytes (stub — NOT real X25519).
*/
int p2p_kx_keypair(uint8_t pk[CRYPTO_KX_PK_SIZE],
                   uint8_t sk[CRYPTO_KX_SK_SIZE]) {
    if (!pk || !sk) return -1;

#ifdef USE_LIBSODIUM
    return crypto_kx_keypair(pk, sk);
#else
    p2p_random_bytes(sk, CRYPTO_KX_SK_SIZE);
    p2p_random_bytes(pk, CRYPTO_KX_PK_SIZE);
    return 0;
#endif
}

/*  Function: p2p_kx_session_keys
    Description:
    Derives rx and tx session keys from an X25519 key exchange.

    Parameters:
    - rx_key: Output buffer for the 32-byte receive key.
    - tx_key: Output buffer for the 32-byte transmit key.
    - our_pk: Our 32-byte public key.
    - our_sk: Our 32-byte secret key.
    - their_pk: Peer's 32-byte public key.
    - is_client: True if we are the client (initiator), false if server (responder).

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Validates pointers.
    2. If USE_LIBSODIUM, delegates to crypto_kx_client_session_keys() or crypto_kx_server_session_keys().
    3. Otherwise, XORs keys as a stub (NOT secure).
    4. Swaps rx/tx for the server side to match the client.
*/
int p2p_kx_session_keys(uint8_t rx_key[CRYPTO_KX_SESSION_SIZE],
                        uint8_t tx_key[CRYPTO_KX_SESSION_SIZE],
                        const uint8_t our_pk[CRYPTO_KX_PK_SIZE],
                        const uint8_t our_sk[CRYPTO_KX_SK_SIZE],
                        const uint8_t their_pk[CRYPTO_KX_PK_SIZE],
                        bool is_client) {
    if (!rx_key || !tx_key || !our_pk || !our_sk || !their_pk) return -1;

#ifdef USE_LIBSODIUM
    if (is_client) {
        return crypto_kx_client_session_keys(rx_key, tx_key,
                                              our_pk, our_sk, their_pk);
    } else {
        return crypto_kx_server_session_keys(rx_key, tx_key,
                                              our_pk, our_sk, their_pk);
    }
#else
    for (int i = 0; i < CRYPTO_KX_SESSION_SIZE; i++) {
        rx_key[i] = our_sk[i] ^ their_pk[i];
        tx_key[i] = our_pk[i] ^ their_pk[i % CRYPTO_KX_PK_SIZE];
    }
    if (!is_client) {
        uint8_t tmp[CRYPTO_KX_SESSION_SIZE];
        memcpy(tmp, rx_key, CRYPTO_KX_SESSION_SIZE);
        memcpy(rx_key, tx_key, CRYPTO_KX_SESSION_SIZE);
        memcpy(tx_key, tmp, CRYPTO_KX_SESSION_SIZE);
        p2p_memzero(tmp, CRYPTO_KX_SESSION_SIZE);
    }
    return 0;
#endif
}