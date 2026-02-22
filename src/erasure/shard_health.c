#define _POSIX_C_SOURCE 200809L
#include "shard_health.h"
#include "shard_helpers.h"
#include "../common/logging.h"

#include <string.h>
#include <unistd.h>

/*  Function: shard_health_check
    Description:
    Runs a health check on all tracked files, updating availability,
    critical counts, and firing callbacks as needed.

    Parameters:
    - mgr: Pointer to the shard_manager_t.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Iterates all files and all shards.
    2. Counts alive holders for each shard.
    3. Updates redundancy, availability, and critical status.
    4. Fires on_shard_critical callback for critical shards.
    5. Updates file-level health summary (available, critical, min_redundancy).
    6. Fires on_file_unrecoverable if fewer than k shards are available.
*/
int shard_health_check(shard_manager_t* mgr) {
    if (!mgr) return -1;

    for (int f = 0; f < mgr->file_count; f++) {
        file_shard_map_t* map = &mgr->files[f];

        map->shards_available = 0;
        map->shards_critical = 0;
        map->min_redundancy = MAX_SHARD_REPLICAS + 1;

        for (int s = 0; s < map->n; s++) {
            shard_descriptor_t* sd = &map->shards[s];

            int alive = 0;
            for (int h = 0; h < sd->holder_count; h++) {
                if (sd->holders[h].alive) alive++;
            }

            sd->redundancy = alive;
            sd->available = (alive > 0);

            if (sd->available) map->shards_available++;
            if (alive <= SHARD_CRITICAL_LEVEL && alive > 0) {
                map->shards_critical++;

                if (mgr->on_shard_critical) {
                    mgr->on_shard_critical(map->file_hash, s, alive,
                                           mgr->callback_data);
                }
            }

            if (alive < map->min_redundancy) {
                map->min_redundancy = alive;
            }
        }

        map->reconstructable = (map->shards_available >= map->k);
        map->last_health_check = shard_get_timestamp_ms();

        if (!map->reconstructable && mgr->on_file_unrecoverable) {
            mgr->on_file_unrecoverable(map->file_hash, mgr->callback_data);
        }
    }

    return 0;
}

/*  Function: health_monitor_thread
    Description:
    Background thread that periodically runs health checks and logs warnings.

    Steps:
    1. Sleeps for SHARD_HEALTH_INTERVAL seconds.
    2. Locks the mutex and runs shard_health_check.
    3. Logs warnings for files with critical shards.
    4. Repeats until health_running is set to false.
*/
static void* health_monitor_thread(void* arg) {
    shard_manager_t* mgr = (shard_manager_t*)arg;

    LOG_INFO("shard: Health monitor started (interval=%ds)", SHARD_HEALTH_INTERVAL);

    while (mgr->health_running) {
        sleep(SHARD_HEALTH_INTERVAL);
        if (!mgr->health_running) break;

        pthread_mutex_lock(&mgr->mutex);
        shard_health_check(mgr);

        for (int f = 0; f < mgr->file_count; f++) {
            file_shard_map_t* map = &mgr->files[f];
            if (map->shards_critical > 0) {
                LOG_WARN("shard: File '%s' has %d critical shards (min redundancy=%d)",
                         map->filename, map->shards_critical, map->min_redundancy);
            }
        }

        pthread_mutex_unlock(&mgr->mutex);
    }

    LOG_INFO("shard: Health monitor stopped");
    return NULL;
}

/*  Function: shard_health_start
    Description:
    Starts the background health monitoring thread.

    Parameters:
    - mgr: Pointer to the shard_manager_t.

    Returns:
    - 0 on success, -1 if already running or thread creation fails.
*/
int shard_health_start(shard_manager_t* mgr) {
    if (!mgr || mgr->health_running) return -1;

    mgr->health_running = true;
    if (pthread_create(&mgr->health_thread, NULL, health_monitor_thread, mgr) != 0) {
        mgr->health_running = false;
        return -1;
    }

    return 0;
}

/*  Function: shard_health_stop
    Description:
    Stops the background health monitoring thread and waits for it to exit.

    Parameters:
    - mgr: Pointer to the shard_manager_t.
*/
void shard_health_stop(shard_manager_t* mgr) {
    if (!mgr || !mgr->health_running) return;

    mgr->health_running = false;
    pthread_join(mgr->health_thread, NULL);
}

/*  Function: shard_peer_heartbeat
    Description:
    Updates the last_seen timestamp and alive flag for a peer across all shards.

    Parameters:
    - mgr: Pointer to the shard_manager_t.
    - peer_id: Peer identifier.

    Steps:
    1. Locks the mutex.
    2. Iterates all files and all shards.
    3. Updates alive and last_seen for matching holders.
    4. Unlocks the mutex.
*/
void shard_peer_heartbeat(shard_manager_t* mgr, const char* peer_id) {
    if (!mgr || !peer_id) return;

    pthread_mutex_lock(&mgr->mutex);

    uint64_t now = shard_get_timestamp_ms();

    for (int f = 0; f < mgr->file_count; f++) {
        for (int s = 0; s < mgr->files[f].n; s++) {
            shard_descriptor_t* sd = &mgr->files[f].shards[s];
            for (int h = 0; h < sd->holder_count; h++) {
                if (strcmp(sd->holders[h].peer_id, peer_id) == 0) {
                    sd->holders[h].alive = true;
                    sd->holders[h].last_seen = now;
                }
            }
        }
    }

    pthread_mutex_unlock(&mgr->mutex);
}

/*  Function: shard_set_callbacks
    Description:
    Sets callback functions for health events (critical shard, unrecoverable file).

    Parameters:
    - mgr: Pointer to the shard_manager_t.
    - on_critical: Callback for shards reaching critical redundancy.
    - on_unrecoverable: Callback for files that can no longer be reconstructed.
    - user_data: Opaque pointer passed to callbacks.
*/
void shard_set_callbacks(shard_manager_t* mgr,
    void (*on_critical)(const char*, int, int, void*),
    void (*on_unrecoverable)(const char*, void*),
    void* user_data) {
    if (!mgr) return;
    mgr->on_shard_critical = on_critical;
    mgr->on_file_unrecoverable = on_unrecoverable;
    mgr->callback_data = user_data;
}