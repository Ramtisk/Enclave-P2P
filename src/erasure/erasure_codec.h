#ifndef P2P_ERASURE_CODEC_H
#define P2P_ERASURE_CODEC_H

#include "erasure_types.h"

/*  ============================================
    ERASURE CODEC API

    Note: Lifecycle, encoding, and decoding operations for Reed-Solomon erasure coding.
    ============================================ */
int erasure_codec_init(erasure_codec_t* codec, int k, int n);
void erasure_codec_cleanup(erasure_codec_t* codec);

int erasure_encode(const erasure_codec_t* codec,
                   const uint8_t* data, size_t data_len,
                   erasure_encoded_t* out);

int erasure_decode(const erasure_codec_t* codec,
                   erasure_encoded_t* encoded,
                   uint8_t* data_out, size_t* data_out_len);

size_t erasure_shard_size(size_t data_len, int k);

#endif