#ifndef P2P_ERASURE_TYPES_H
#define P2P_ERASURE_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*  ============================================
    REED-SOLOMON ERASURE CODING CONSTANTS

    Note: Splits data into k data shards and generates (n-k) parity shards.
    Any k of n shards are sufficient to reconstruct the original data.
    Uses systematic encoding: first k shards contain original data verbatim.
    All arithmetic is over GF(2^8), limiting total shards to 255.
    ============================================ */
#define RS_MAX_TOTAL_SHARDS  255
#define RS_MAX_DATA_SHARDS   128
#define RS_MAX_PARITY_SHARDS 127

/*  ============================================
    ERASURE CODEC

    Note: Holds the encoding matrix and parameters for a specific k/n configuration.
    - k: Number of data shards.
    - n: Total shards (k + parity).
    - parity: Number of parity shards (n - k).
    - encode_matrix: n × k matrix. First k rows = identity (systematic).
      Last (n-k) rows = parity coefficients.
    - parity_matrix: Pointer into encode_matrix at the parity rows.
    - initialized: True after successful init.
    ============================================ */
typedef struct {
    int k;
    int n;
    int parity;
    uint8_t* encode_matrix;
    uint8_t* parity_matrix;
    bool initialized;
} erasure_codec_t;

/*  ============================================
    ENCODED DATA

    Note: Holds the result of encoding a data buffer.
    - shards: Array of n shard buffers.
    - shard_size: Size of each shard in bytes.
    - n: Total shard count.
    - k: Data shard count.
    - present: Boolean array indicating which shards are available.
    - original_size: Original data size before padding.
    ============================================ */
typedef struct {
    uint8_t** shards;
    size_t shard_size;
    int n;
    int k;
    bool* present;
    size_t original_size;
} erasure_encoded_t;

#endif