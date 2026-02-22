#ifndef P2P_SHARD_HEALTH_H
#define P2P_SHARD_HEALTH_H

#include "shard_types.h"

/*  ============================================
    SHARD HEALTH MONITORING API

    Note: Functions for checking shard redundancy levels,
    running background health monitoring, and managing callbacks.
    ============================================ */
int shard_health_check(shard_manager_t* mgr);
int shard_health_start(shard_manager_t* mgr);
void shard_health_stop(shard_manager_t* mgr);
void shard_peer_heartbeat(shard_manager_t* mgr, const char* peer_id);
void shard_set_callbacks(shard_manager_t* mgr,
    void (*on_critical)(const char* file_hash, int shard_index,
                        int redundancy, void* data),
    void (*on_unrecoverable)(const char* file_hash, void* data),
    void* user_data);

#endif