#ifndef P2P_CRYPTO_HYBRID_SERIAL_H
#define P2P_CRYPTO_HYBRID_SERIAL_H

#include "hybrid_types.h"

/*  ============================================
    HYBRID BUNDLE SERIALIZATION API

    Note: Functions for serializing and deserializing hybrid key bundles
    for transmission over the network.
    ============================================ */
int hybrid_bundle_serialize(const hybrid_key_bundle_t* bundle,
                            uint8_t* buf, size_t buf_size, size_t* out_len);

int hybrid_bundle_deserialize(hybrid_key_bundle_t* bundle,
                              const uint8_t* buf, size_t buf_len);

#endif