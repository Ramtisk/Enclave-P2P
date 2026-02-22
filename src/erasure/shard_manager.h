#ifndef P2P_SHARD_MANAGER_H
#define P2P_SHARD_MANAGER_H

#include "shard_types.h"

/*  ============================================
    SHARD MANAGER API

    Note: Lifecycle and file registration operations.
    ============================================ */
int shard_manager_init(shard_manager_t* mgr, const char* group_id,
                       const char* shard_dir);
void shard_manager_cleanup(shard_manager_t* mgr);

int shard_register_file(shard_manager_t* mgr,
                        const char* file_hash, const char* filename,
                        size_t original_size, int k, int n, size_t shard_size);
int shard_unregister_file(shard_manager_t* mgr, const char* file_hash);
file_shard_map_t* shard_find_file(shard_manager_t* mgr, const char* file_hash);

#endif