#include "erasure_data.h"
#include "../common/logging.h"

#include <stdlib.h>
#include <string.h>

/*  Function: erasure_encoded_alloc
    Description:
    Allocates shard buffers and the present array for an encoded data structure.

    Parameters:
    - enc: Pointer to the erasure_encoded_t structure.
    - k: Number of data shards.
    - n: Total shard count.
    - shard_size: Size of each shard buffer.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Clears the structure.
    2. Sets k, n, and shard_size.
    3. Allocates an array of n shard pointers and n booleans.
    4. Allocates each shard buffer with calloc (zero-filled).
    5. Marks all shards as not present.
*/
int erasure_encoded_alloc(erasure_encoded_t* enc, int k, int n, size_t shard_size) {
    if (!enc) return -1;

    memset(enc, 0, sizeof(erasure_encoded_t));

    enc->k = k;
    enc->n = n;
    enc->shard_size = shard_size;

    enc->shards = calloc(n, sizeof(uint8_t*));
    enc->present = calloc(n, sizeof(bool));

    if (!enc->shards || !enc->present) {
        erasure_encoded_free(enc);
        return -1;
    }

    for (int i = 0; i < n; i++) {
        enc->shards[i] = calloc(1, shard_size);
        if (!enc->shards[i]) {
            erasure_encoded_free(enc);
            return -1;
        }
        enc->present[i] = false;
    }

    return 0;
}

/*  Function: erasure_encoded_free
    Description:
    Frees all shard buffers and the present array.

    Parameters:
    - enc: Pointer to the erasure_encoded_t structure.

    Steps:
    1. Frees each individual shard buffer.
    2. Frees the shards pointer array.
    3. Frees the present boolean array.
*/
void erasure_encoded_free(erasure_encoded_t* enc) {
    if (!enc) return;

    if (enc->shards) {
        for (int i = 0; i < enc->n; i++) {
            if (enc->shards[i]) {
                free(enc->shards[i]);
                enc->shards[i] = NULL;
            }
        }
        free(enc->shards);
        enc->shards = NULL;
    }

    if (enc->present) {
        free(enc->present);
        enc->present = NULL;
    }
}

/*  Function: erasure_mark_lost
    Description:
    Marks a shard as lost (unavailable for reconstruction).

    Parameters:
    - enc: Pointer to the erasure_encoded_t structure.
    - shard_index: Index of the shard to mark as lost.

    Steps:
    1. Validates the index.
    2. Sets present[shard_index] to false.
*/
void erasure_mark_lost(erasure_encoded_t* enc, int shard_index) {
    if (!enc || shard_index < 0 || shard_index >= enc->n) return;
    enc->present[shard_index] = false;
    LOG_DEBUG("erasure: Shard %d marked as lost", shard_index);
}

/*  Function: erasure_count_available
    Description:
    Counts how many shards are currently marked as present.

    Parameters:
    - enc: Pointer to the erasure_encoded_t structure.

    Returns:
    - Number of available shards.
*/
int erasure_count_available(const erasure_encoded_t* enc) {
    if (!enc) return 0;
    int count = 0;
    for (int i = 0; i < enc->n; i++) {
        if (enc->present[i]) count++;
    }
    return count;
}

/*  Function: erasure_can_reconstruct
    Description:
    Checks whether enough shards are available to reconstruct the original data.

    Parameters:
    - enc: Pointer to the erasure_encoded_t structure.

    Returns:
    - true if at least k shards are available, false otherwise.
*/
bool erasure_can_reconstruct(const erasure_encoded_t* enc) {
    if (!enc) return false;
    return erasure_count_available(enc) >= enc->k;
}