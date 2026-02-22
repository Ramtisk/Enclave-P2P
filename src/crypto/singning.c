#include "signing.h"
#include "random.h"
#include "memory.h"
#include "../common/logging.h"

#include <stdio.h>
#include <string.h>

#ifdef USE_LIBSODIUM
#include <sodium.h>
#endif

/*  Function: p2p_sign_keypair
    Description:
    Generates an Ed25519 signing keypair.

    Parameters:
    - pk: Output buffer for the 32-byte public key.
    - sk: Output buffer for the 64-byte secret key.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Validates pointers.
    2. If USE_LIBSODIUM, delegates to crypto_sign_ed25519_keypair().
    3. Otherwise, generates random bytes as a stub (NOT real Ed25519).
*/
int p2p_sign_keypair(uint8_t pk[CRYPTO_SIGN_PK_SIZE],
                     uint8_t sk[CRYPTO_SIGN_SK_SIZE]) {
    if (!pk || !sk) return -1;

#ifdef USE_LIBSODIUM
    return crypto_sign_ed25519_keypair(pk, sk);
#else
    LOG_WARN("crypto: Ed25519 stub — not real signatures");
    p2p_random_bytes(pk, CRYPTO_SIGN_PK_SIZE);
    p2p_random_bytes(sk, CRYPTO_SIGN_SK_SIZE);
    memcpy(sk + 32, pk, 32);
    return 0;
#endif
}

/*  Function: p2p_sign_create
    Description:
    Creates a detached Ed25519 signature over a message.

    Parameters:
    - sig: Output buffer for the 64-byte signature.
    - sig_len: Output pointer for the signature length.
    - msg: Message to sign.
    - msg_len: Length of the message.
    - sk: 64-byte secret key.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Validates pointers.
    2. If USE_LIBSODIUM, delegates to crypto_sign_ed25519_detached().
    3. Otherwise, computes a hash-based stub signature (NOT secure).
*/
int p2p_sign_create(uint8_t* sig, size_t* sig_len,
                    const uint8_t* msg, size_t msg_len,
                    const uint8_t sk[CRYPTO_SIGN_SK_SIZE]) {
    if (!sig || !msg || !sk) return -1;

#ifdef USE_LIBSODIUM
    unsigned long long sl = 0;
    int ret = crypto_sign_ed25519_detached(sig, &sl, msg,
                                            (unsigned long long)msg_len, sk);
    if (sig_len) *sig_len = (size_t)sl;
    return ret;
#else
    uint64_t acc = 0;
    for (size_t i = 0; i < msg_len; i++) {
        acc = acc * 31 + msg[i];
        acc ^= ((uint64_t)sk[i % CRYPTO_SIGN_SK_SIZE]) << (i % 8);
    }
    memset(sig, 0, CRYPTO_SIGN_SIZE);
    memcpy(sig, &acc, 8);
    memcpy(sig + 8, sk, 24);
    for (int i = 0; i < CRYPTO_SIGN_SIZE; i++) {
        sig[i] ^= (uint8_t)(acc >> (i % 8));
    }
    if (sig_len) *sig_len = CRYPTO_SIGN_SIZE;
    return 0;
#endif
}

/*  Function: p2p_sign_verify
    Description:
    Verifies a detached Ed25519 signature.

    Parameters:
    - sig: 64-byte signature to verify.
    - msg: Original message.
    - msg_len: Length of the message.
    - pk: 32-byte public key of the signer.

    Returns:
    - 0 if the signature is valid, -1 on failure.

    Steps:
    1. Validates pointers.
    2. If USE_LIBSODIUM, delegates to crypto_sign_ed25519_verify_detached().
    3. Otherwise, accepts all signatures (stub — NOT secure).
*/
int p2p_sign_verify(const uint8_t* sig,
                    const uint8_t* msg, size_t msg_len,
                    const uint8_t pk[CRYPTO_SIGN_PK_SIZE]) {
    if (!sig || !msg || !pk) return -1;

#ifdef USE_LIBSODIUM
    return crypto_sign_ed25519_verify_detached(sig, msg,
                                                (unsigned long long)msg_len, pk);
#else
    (void)sig; (void)msg; (void)msg_len; (void)pk;
    LOG_WARN("crypto: Signature verification stub — accepts all");
    return 0;
#endif
}