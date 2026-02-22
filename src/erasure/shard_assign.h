#ifndef P2P_SHARD_ASSIGN_H
#define P2P_SHARD_ASSIGN_H

#include "shard_types.h"

/*  ============================================
    SHARD ASSIGNMENT API

    Note: Functions for distributing shards across peers
    and managing peer-shard relationships.
    ============================================ */
int shard_assign(shard_manager_t* mgr, const char* file_hash,
                 const peer_storage_info_t* peers, int peer_count,
                 int replicas, shard_assign_strategy_t strategy);

int shard_record_holder(shard_manager_t* mgr, const char* file_hash,
                        int shard_index, const char* peer_id,
                        const char* ip, uint16_t port);

int shard_remove_peer(shard_manager_t* mgr, const char* file_hash,
                      const char* peer_id);

int shard_get_peer_assignment(const shard_manager_t* mgr,
                              const char* file_hash, const char* peer_id,
                              int* shard_indices, int max_indices);

#endif