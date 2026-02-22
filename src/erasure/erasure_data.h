#ifndef P2P_ERASURE_DATA_H
#define P2P_ERASURE_DATA_H

#include "erasure_types.h"

/*  ============================================
    ENCODED DATA MANAGEMENT API

    Note: Functions for allocating, freeing, and querying
    the encoded shard data structure.
    ============================================ */
int erasure_encoded_alloc(erasure_encoded_t* enc, int k, int n, size_t shard_size);
void erasure_encoded_free(erasure_encoded_t* enc);
void erasure_mark_lost(erasure_encoded_t* enc, int shard_index);
int erasure_count_available(const erasure_encoded_t* enc);
bool erasure_can_reconstruct(const erasure_encoded_t* enc);

#endif