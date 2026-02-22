#ifndef P2P_IDENTITY_PEER_H
#define P2P_IDENTITY_PEER_H

#include "identity_types.h"

/*  ============================================
    PEER IDENTITY API

    Note: Functions for generating, deriving, signing,
    and verifying long-term peer identities.
    ============================================ */
int identity_generate(peer_identity_t *id);
void identity_derive_id(peer_identity_t *id);
int identity_sign(const peer_identity_t *id,
                  uint8_t *sig, size_t *sig_len,
                  const uint8_t *data, size_t data_len);
int identity_verify(const uint8_t pk[CRYPTO_SIGN_PK_SIZE],
                    const uint8_t *sig,
                    const uint8_t *data, size_t data_len);
void identity_fingerprint_hex(const peer_identity_t *id,
                              char *hex_out, size_t hex_len);

#endif