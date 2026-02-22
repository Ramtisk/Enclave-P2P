#include "erasure_codec.h"
#include "erasure_data.h"
#include "galois.h"
#include "../common/logging.h"

#include <stdlib.h>
#include <string.h>

/*  Function: erasure_codec_init
    Description:
    Creates a new Reed-Solomon codec with k data shards and n total shards.
    Builds a systematic encoding matrix using Cauchy construction.

    Parameters:
    - codec: Pointer to the erasure_codec_t structure.
    - k: Number of data shards (1 to RS_MAX_DATA_SHARDS).
    - n: Total shards (k to RS_MAX_TOTAL_SHARDS).

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Validates k and n parameters.
    2. Clears the codec structure and initializes GF(2^8) tables.
    3. Allocates the n×k encoding matrix.
    4. Builds a Cauchy matrix (n × k).
    5. Copies and inverts the top k×k submatrix.
    6. Multiplies full Cauchy matrix by the inverse to get systematic form.
    7. Verifies top k rows are identity.
    8. Sets parity_matrix pointer to the bottom (n-k) rows.
    9. Marks codec as initialized and logs parameters.
*/
int erasure_codec_init(erasure_codec_t* codec, int k, int n) {
    if (!codec) return -1;
    if (k < 1 || k > RS_MAX_DATA_SHARDS) {
        LOG_ERROR("erasure: k=%d out of range [1, %d]", k, RS_MAX_DATA_SHARDS);
        return -1;
    }
    if (n < k || n > RS_MAX_TOTAL_SHARDS) {
        LOG_ERROR("erasure: n=%d out of range [k=%d, %d]", n, k, RS_MAX_TOTAL_SHARDS);
        return -1;
    }

    memset(codec, 0, sizeof(erasure_codec_t));
    gf_init();

    codec->k = k;
    codec->n = n;
    codec->parity = n - k;

    codec->encode_matrix = malloc(n * k);
    if (!codec->encode_matrix) {
        LOG_ERROR("erasure: Failed to allocate encode matrix");
        return -1;
    }

    uint8_t* cauchy = malloc(n * k);
    if (!cauchy) {
        free(codec->encode_matrix);
        return -1;
    }
    gf_matrix_cauchy(cauchy, n, k);

    uint8_t* top_inv = malloc(k * k);
    if (!top_inv) {
        free(cauchy);
        free(codec->encode_matrix);
        return -1;
    }

    for (int i = 0; i < k; i++) {
        memcpy(top_inv + i * k, cauchy + i * k, k);
    }

    if (gf_matrix_invert(top_inv, k) != 0) {
        LOG_ERROR("erasure: Top submatrix is singular — bad parameters");
        free(top_inv);
        free(cauchy);
        free(codec->encode_matrix);
        return -1;
    }

    gf_matrix_multiply(codec->encode_matrix, cauchy, n, k, top_inv, k);

    free(top_inv);
    free(cauchy);

    for (int i = 0; i < k; i++) {
        for (int j = 0; j < k; j++) {
            uint8_t expected = (i == j) ? 1 : 0;
            if (codec->encode_matrix[i * k + j] != expected) {
                LOG_WARN("erasure: Systematic check failed at [%d][%d]: got %d, expected %d",
                         i, j, codec->encode_matrix[i * k + j], expected);
            }
        }
    }

    codec->parity_matrix = codec->encode_matrix + k * k;
    codec->initialized = true;

    LOG_INFO("erasure: Reed-Solomon codec initialized (k=%d, n=%d, parity=%d)",
             k, n, codec->parity);
    LOG_INFO("erasure:   Fault tolerance: %d shard failures (%.0f%%)",
             codec->parity, (double)codec->parity / n * 100.0);

    return 0;
}

/*  Function: erasure_codec_cleanup
    Description:
    Frees the encoding matrix and resets the codec.

    Parameters:
    - codec: Pointer to the erasure_codec_t structure.

    Steps:
    1. Frees the encode_matrix (parity_matrix is a pointer into it).
    2. Marks the codec as not initialized.
*/
void erasure_codec_cleanup(erasure_codec_t* codec) {
    if (!codec) return;

    if (codec->encode_matrix) {
        free(codec->encode_matrix);
        codec->encode_matrix = NULL;
        codec->parity_matrix = NULL;
    }

    codec->initialized = false;
    LOG_DEBUG("erasure: Codec cleaned up");
}

/*  Function: erasure_shard_size
    Description:
    Computes the shard size for a given data length and k.

    Parameters:
    - data_len: Total data length in bytes.
    - k: Number of data shards.

    Returns:
    - Shard size in bytes (ceil(data_len / k)).
*/
size_t erasure_shard_size(size_t data_len, int k) {
    if (k <= 0) return 0;
    return (data_len + k - 1) / k;
}

/*  Function: erasure_encode
    Description:
    Encodes data into n shards (k data + parity) using the codec's encoding matrix.

    Parameters:
    - codec: Pointer to the initialized erasure_codec_t.
    - data: Input data buffer.
    - data_len: Length of input data.
    - out: Pointer to erasure_encoded_t to populate.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Computes shard size and allocates output structure.
    2. Splits data into k data shards (zero-padded last shard).
    3. Marks all data shards as present.
    4. Generates parity shards: parity[p] = Σ(parity_matrix[p][j] * data[j]).
    5. Marks all parity shards as present.
    6. Logs encoding statistics.
*/
int erasure_encode(const erasure_codec_t* codec,
                   const uint8_t* data, size_t data_len,
                   erasure_encoded_t* out) {
    if (!codec || !codec->initialized || !data || !out) return -1;

    size_t shard_sz = erasure_shard_size(data_len, codec->k);

    if (erasure_encoded_alloc(out, codec->k, codec->n, shard_sz) != 0) {
        return -1;
    }

    out->original_size = data_len;

    for (int i = 0; i < codec->k; i++) {
        size_t offset = (size_t)i * shard_sz;
        size_t copy_len = shard_sz;

        if (offset + copy_len > data_len) {
            size_t actual = (offset < data_len) ? (data_len - offset) : 0;
            if (actual > 0) {
                memcpy(out->shards[i], data + offset, actual);
            }
        } else {
            memcpy(out->shards[i], data + offset, copy_len);
        }
        out->present[i] = true;
    }

    const uint8_t** data_ptrs = (const uint8_t**)malloc(codec->k * sizeof(uint8_t*));
    if (!data_ptrs) return -1;

    for (int j = 0; j < codec->k; j++) {
        data_ptrs[j] = out->shards[j];
    }

    for (int p = 0; p < codec->parity; p++) {
        int shard_idx = codec->k + p;
        memset(out->shards[shard_idx], 0, shard_sz);

        for (int j = 0; j < codec->k; j++) {
            uint8_t coeff = codec->parity_matrix[p * codec->k + j];
            if (coeff == 0) continue;
            gf_vec_muladd(out->shards[shard_idx], data_ptrs[j], coeff, shard_sz);
        }
        out->present[shard_idx] = true;
    }

    free(data_ptrs);

    LOG_INFO("erasure: Encoded %zu bytes → %d shards of %zu bytes each "
             "(total %zu bytes, overhead %.1f%%)",
             data_len, codec->n, shard_sz,
             (size_t)codec->n * shard_sz,
             ((double)codec->n * shard_sz - data_len) / data_len * 100.0);

    return 0;
}

/*  Function: erasure_decode
    Description:
    Reconstructs original data from any k available shards.

    Parameters:
    - codec: Pointer to the initialized erasure_codec_t.
    - encoded: Pointer to erasure_encoded_t with at least k present shards.
    - data_out: Output buffer (at least original_size bytes).
    - data_out_len: Output pointer for actual decoded size.

    Returns:
    - 0 on success, -1 if not enough shards or decoding fails.

    Steps:
    1. Checks that at least k shards are available.
    2. Fast path: if all k data shards are present, concatenates them.
    3. Slow path: picks first k available shards, extracts k×k submatrix
       from encoding matrix, inverts it, and multiplies by available shards.
    4. Copies reconstructed data to output buffer, trimming to original_size.
    5. Logs reconstruction statistics.
*/
int erasure_decode(const erasure_codec_t* codec,
                   erasure_encoded_t* encoded,
                   uint8_t* data_out, size_t* data_out_len) {
    if (!codec || !codec->initialized || !encoded || !data_out) return -1;

    int available = erasure_count_available(encoded);
    if (available < codec->k) {
        LOG_ERROR("erasure: Not enough shards for reconstruction "
                  "(%d available, %d needed)", available, codec->k);
        return -1;
    }

    bool all_data_present = true;
    for (int i = 0; i < codec->k; i++) {
        if (!encoded->present[i]) {
            all_data_present = false;
            break;
        }
    }

    if (all_data_present) {
        size_t offset = 0;
        for (int i = 0; i < codec->k; i++) {
            size_t copy_len = encoded->shard_size;
            if (offset + copy_len > encoded->original_size) {
                copy_len = encoded->original_size - offset;
            }
            memcpy(data_out + offset, encoded->shards[i], copy_len);
            offset += copy_len;
        }
        if (data_out_len) *data_out_len = encoded->original_size;
        LOG_DEBUG("erasure: Fast decode — all data shards present");
        return 0;
    }

    int* shard_indices = malloc(codec->k * sizeof(int));
    if (!shard_indices) return -1;

    int idx = 0;
    for (int i = 0; i < encoded->n && idx < codec->k; i++) {
        if (encoded->present[i]) {
            shard_indices[idx++] = i;
        }
    }

    uint8_t* submatrix = malloc(codec->k * codec->k);
    if (!submatrix) {
        free(shard_indices);
        return -1;
    }

    for (int i = 0; i < codec->k; i++) {
        int row = shard_indices[i];
        memcpy(submatrix + i * codec->k,
               codec->encode_matrix + row * codec->k,
               codec->k);
    }

    uint8_t* decode_matrix = malloc(codec->k * codec->k);
    if (!decode_matrix) {
        free(submatrix);
        free(shard_indices);
        return -1;
    }
    memcpy(decode_matrix, submatrix, codec->k * codec->k);

    if (gf_matrix_invert(decode_matrix, codec->k) != 0) {
        LOG_ERROR("erasure: Decode matrix is singular — cannot reconstruct");
        free(decode_matrix);
        free(submatrix);
        free(shard_indices);
        return -1;
    }

    uint8_t* temp_shard = malloc(encoded->shard_size);
    if (!temp_shard) {
        free(decode_matrix);
        free(submatrix);
        free(shard_indices);
        return -1;
    }

    size_t offset = 0;
    for (int j = 0; j < codec->k; j++) {
        memset(temp_shard, 0, encoded->shard_size);

        for (int i = 0; i < codec->k; i++) {
            uint8_t coeff = decode_matrix[j * codec->k + i];
            if (coeff == 0) continue;
            gf_vec_muladd(temp_shard, encoded->shards[shard_indices[i]],
                          coeff, encoded->shard_size);
        }

        size_t copy_len = encoded->shard_size;
        if (offset + copy_len > encoded->original_size) {
            copy_len = (offset < encoded->original_size) ?
                       (encoded->original_size - offset) : 0;
        }
        if (copy_len > 0) {
            memcpy(data_out + offset, temp_shard, copy_len);
        }
        offset += encoded->shard_size;
    }

    if (data_out_len) *data_out_len = encoded->original_size;

    int reconstructed = 0;
    for (int i = 0; i < codec->k; i++) {
        if (!encoded->present[i]) reconstructed++;
    }

    LOG_INFO("erasure: Reconstructed %zu bytes from %d/%d shards "
             "(%d data shards rebuilt)",
             encoded->original_size, available, encoded->n, reconstructed);

    free(temp_shard);
    free(decode_matrix);
    free(submatrix);
    free(shard_indices);

    return 0;
}