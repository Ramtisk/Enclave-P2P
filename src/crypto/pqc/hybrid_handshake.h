#ifndef P2P_CRYPTO_HYBRID_HANDSHAKE_H
#define P2P_CRYPTO_HYBRID_HANDSHAKE_H

#include "hybrid_types.h"

/*  ============================================
    HYBRID HANDSHAKE API

    Note: Functions for the full hybrid handshake lifecycle:
    init, cleanup, bundle generation/processing, encapsulation,
    decapsulation, and final key derivation.
    ============================================ */
int hybrid_handshake_init(hybrid_handshake_t* hs, bool is_initiator);
void hybrid_handshake_cleanup(hybrid_handshake_t* hs);

int hybrid_generate_bundle(hybrid_handshake_t* hs,
                           hybrid_key_bundle_t* bundle_out,
                           const uint8_t identity_sk[CRYPTO_SIGN_SK_SIZE],
                           const uint8_t identity_pk[CRYPTO_SIGN_PK_SIZE]);

int hybrid_process_bundle(hybrid_handshake_t* hs,
                          const hybrid_key_bundle_t* peer_bundle);

int hybrid_encapsulate(hybrid_handshake_t* hs,
                       uint8_t* ct_out, size_t ct_buf_size);

int hybrid_decapsulate(hybrid_handshake_t* hs,
                       const uint8_t* ct, size_t ct_len);

int hybrid_derive_keys(hybrid_handshake_t* hs);

#endif