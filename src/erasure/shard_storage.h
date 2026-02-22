#ifndef P2P_SHARD_STORAGE_H
#define P2P_SHARD_STORAGE_H

#include "shard_types.h"

/*  ============================================
    LOCAL SHARD STORAGE API

    Note: Functions for saving, loading, and checking local shard files on disk.
    ============================================ */
int shard_store_local(shard_manager_t* mgr, const char* file_hash,
                      int shard_index, const uint8_t* data, size_t len);

int shard_load_local(shard_manager_t* mgr, const char* file_hash,
                     int shard_index, uint8_t* data, size_t max_len,
                     size_t* actual_len);

bool shard_exists_local(const shard_manager_t* mgr, const char* file_hash,
                        int shard_index);

#endif