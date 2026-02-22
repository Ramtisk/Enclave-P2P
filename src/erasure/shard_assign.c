#define _POSIX_C_SOURCE 200809L
#include "shard_assign.h"
#include "shard_manager.h"
#include "shard_health.h"
#include "shard_helpers.h"
#include "../common/logging.h"

#include <string.h>

/*  Function: shard_assign
    Description:
    Distributes shards across peers according to the chosen strategy and replica count.

    Parameters:
    - mgr: Pointer to the shard_manager_t.
    - file_hash: File hash to assign shards for.
    - peers: Array of peer storage info.
    - peer_count: Number of available peers.
    - replicas: Number of copies per shard (1 = no redundancy).
    - strategy: ROUND_ROBIN, RANDOM, or CAPACITY_BASED.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Validates parameters and clamps replicas.
    2. Finds the file's shard map.
    3. For each shard, assigns replicas to peers based on strategy.
    4. Avoids assigning the same shard to the same peer twice.
    5. Updates redundancy and availability status.
    6. Triggers a health check.
*/
int shard_assign(shard_manager_t* mgr, const char* file_hash,
                 const peer_storage_info_t* peers, int peer_count,
                 int replicas, shard_assign_strategy_t strategy) {
    if (!mgr || !file_hash || !peers || peer_count <= 0) return -1;
    if (replicas < 1) replicas = 1;
    if (replicas > MAX_SHARD_REPLICAS) replicas = MAX_SHARD_REPLICAS;
    if (replicas > peer_count) replicas = peer_count;

    pthread_mutex_lock(&mgr->mutex);

    file_shard_map_t* map = shard_find_file(mgr, file_hash);
    if (!map) {
        pthread_mutex_unlock(&mgr->mutex);
        LOG_ERROR("shard: File not found for assignment");
        return -1;
    }

    int assigned = 0;

    for (int s = 0; s < map->n; s++) {
        shard_descriptor_t* sd = &map->shards[s];
        sd->holder_count = 0;

        for (int r = 0; r < replicas; r++) {
            int peer_idx;

            switch (strategy) {
                case ASSIGN_ROUND_ROBIN:
                    peer_idx = (s * replicas + r) % peer_count;
                    break;

                case ASSIGN_RANDOM: {
                    uint32_t hash_val = (uint32_t)(s * 7919 + r * 104729);
                    peer_idx = (int)(hash_val % (uint32_t)peer_count);
                    break;
                }

                case ASSIGN_CAPACITY_BASED: {
                    int best = 0;
                    uint64_t best_avail = 0;
                    for (int p = 0; p < peer_count; p++) {
                        uint64_t avail = peers[p].capacity_bytes - peers[p].used_bytes;
                        if (avail > best_avail && peers[p].online) {
                            best_avail = avail;
                            best = p;
                        }
                    }
                    peer_idx = best;
                    break;
                }

                default:
                    peer_idx = (s + r) % peer_count;
                    break;
            }

            bool duplicate = false;
            for (int h = 0; h < sd->holder_count; h++) {
                if (strcmp(sd->holders[h].peer_id, peers[peer_idx].peer_id) == 0) {
                    duplicate = true;
                    break;
                }
            }

            if (!duplicate && sd->holder_count < MAX_SHARD_REPLICAS) {
                strncpy(sd->holders[sd->holder_count].peer_id,
                        peers[peer_idx].peer_id, MAX_ID_LENGTH - 1);
                strncpy(sd->holders[sd->holder_count].ip,
                        peers[peer_idx].ip, 45);
                sd->holders[sd->holder_count].port = peers[peer_idx].port;
                sd->holders[sd->holder_count].alive = peers[peer_idx].online;
                sd->holders[sd->holder_count].last_seen = shard_get_timestamp_ms();
                sd->holder_count++;
                assigned++;
            }
        }

        sd->redundancy = sd->holder_count;
        sd->available = (sd->holder_count > 0);
    }

    shard_health_check(mgr);

    pthread_mutex_unlock(&mgr->mutex);

    LOG_INFO("shard: Assigned %d shard-replicas across %d peers "
             "(strategy=%d, replicas=%d)",
             assigned, peer_count, strategy, replicas);
    return 0;
}

/*  Function: shard_record_holder
    Description:
    Records that a specific peer holds a copy of a shard.

    Parameters:
    - mgr: Pointer to the shard_manager_t.
    - file_hash: File hash.
    - shard_index: Shard index.
    - peer_id: Peer identifier.
    - ip: Peer IP address.
    - port: Peer port.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Finds the file and validates the shard index.
    2. Updates last_seen if peer is already recorded.
    3. Otherwise adds the peer as a new holder.
*/
int shard_record_holder(shard_manager_t* mgr, const char* file_hash,
                        int shard_index, const char* peer_id,
                        const char* ip, uint16_t port) {
    if (!mgr || !file_hash || !peer_id) return -1;

    pthread_mutex_lock(&mgr->mutex);

    file_shard_map_t* map = shard_find_file(mgr, file_hash);
    if (!map || shard_index < 0 || shard_index >= map->n) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }

    shard_descriptor_t* sd = &map->shards[shard_index];

    for (int i = 0; i < sd->holder_count; i++) {
        if (strcmp(sd->holders[i].peer_id, peer_id) == 0) {
            sd->holders[i].alive = true;
            sd->holders[i].last_seen = shard_get_timestamp_ms();
            pthread_mutex_unlock(&mgr->mutex);
            return 0;
        }
    }

    if (sd->holder_count >= MAX_SHARD_REPLICAS) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }

    int idx = sd->holder_count++;
    strncpy(sd->holders[idx].peer_id, peer_id, MAX_ID_LENGTH - 1);
    if (ip) strncpy(sd->holders[idx].ip, ip, 45);
    sd->holders[idx].port = port;
    sd->holders[idx].alive = true;
    sd->holders[idx].last_seen = shard_get_timestamp_ms();

    sd->redundancy = sd->holder_count;
    sd->available = true;

    pthread_mutex_unlock(&mgr->mutex);
    return 0;
}

/*  Function: shard_remove_peer
    Description:
    Removes a peer from all shard holder lists for a given file.

    Parameters:
    - mgr: Pointer to the shard_manager_t.
    - file_hash: File hash.
    - peer_id: Peer to remove.

    Returns:
    - 0 if at least one removal occurred, -1 if peer not found.

    Steps:
    1. Finds the file's shard map.
    2. Iterates all shards, removing the peer from holder lists.
    3. Shifts remaining holders and updates redundancy/availability.
    4. Triggers a health check if any removals occurred.
*/
int shard_remove_peer(shard_manager_t* mgr, const char* file_hash,
                      const char* peer_id) {
    if (!mgr || !file_hash || !peer_id) return -1;

    pthread_mutex_lock(&mgr->mutex);

    file_shard_map_t* map = shard_find_file(mgr, file_hash);
    if (!map) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }

    int removed = 0;
    for (int s = 0; s < map->n; s++) {
        shard_descriptor_t* sd = &map->shards[s];
        for (int h = 0; h < sd->holder_count; h++) {
            if (strcmp(sd->holders[h].peer_id, peer_id) == 0) {
                for (int j = h; j < sd->holder_count - 1; j++) {
                    sd->holders[j] = sd->holders[j + 1];
                }
                sd->holder_count--;
                removed++;

                int alive = 0;
                for (int a = 0; a < sd->holder_count; a++) {
                    if (sd->holders[a].alive) alive++;
                }
                sd->redundancy = alive;
                sd->available = (alive > 0);
                break;
            }
        }
    }

    pthread_mutex_unlock(&mgr->mutex);

    if (removed > 0) {
        LOG_INFO("shard: Removed peer '%s' from %d shard(s)", peer_id, removed);
        shard_health_check(mgr);
    }

    return removed > 0 ? 0 : -1;
}

/*  Function: shard_get_peer_assignment
    Description:
    Returns a list of shard indices that a specific peer holds for a given file.

    Parameters:
    - mgr: Pointer to the shard_manager_t.
    - file_hash: File hash.
    - peer_id: Peer to query.
    - shard_indices: Output array for shard indices.
    - max_indices: Maximum entries in the output array.

    Returns:
    - Number of shard indices written to the array.
*/
int shard_get_peer_assignment(const shard_manager_t* mgr,
                              const char* file_hash, const char* peer_id,
                              int* shard_indices, int max_indices) {
    if (!mgr || !file_hash || !peer_id || !shard_indices) return 0;

    const file_shard_map_t* map = NULL;
    for (int i = 0; i < mgr->file_count; i++) {
        if (memcmp(mgr->files[i].file_hash, file_hash, SHARD_HASH_SIZE) == 0) {
            map = &mgr->files[i];
            break;
        }
    }
    if (!map) return 0;

    int count = 0;
    for (int s = 0; s < map->n && count < max_indices; s++) {
        for (int h = 0; h < map->shards[s].holder_count; h++) {
            if (strcmp(map->shards[s].holders[h].peer_id, peer_id) == 0) {
                shard_indices[count++] = s;
                break;
            }
        }
    }

    return count;
}