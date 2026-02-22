#define _POSIX_C_SOURCE 200809L
#include "shard_manager.h"
#include "shard_health.h"
#include "shard_helpers.h"
#include "../common/logging.h"

#include <stdlib.h>
#include <string.h>

/*  Function: shard_manager_init
    Description:
    Initializes the shard manager, creates the shard storage directory,
    and allocates the initial file array.

    Parameters:
    - mgr: Pointer to the shard_manager_t structure.
    - group_id: Group identifier.
    - shard_dir: Path for local shard storage (NULL for default "data/shards").

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Clears the manager structure.
    2. Sets group_id and shard_dir (with default fallback).
    3. Ensures the shard directory exists.
    4. Allocates initial file array (capacity 16).
    5. Initializes the mutex.
    6. Logs initialization.
*/
int shard_manager_init(shard_manager_t* mgr, const char* group_id,
                       const char* shard_dir) {
    if (!mgr) return -1;

    memset(mgr, 0, sizeof(shard_manager_t));

    if (group_id) {
        strncpy(mgr->group_id, group_id, MAX_ID_LENGTH - 1);
    }

    if (shard_dir) {
        strncpy(mgr->shard_dir, shard_dir, sizeof(mgr->shard_dir) - 1);
        shard_ensure_directory(shard_dir);
    } else {
        strncpy(mgr->shard_dir, "data/shards", sizeof(mgr->shard_dir) - 1);
        shard_ensure_directory("data");
        shard_ensure_directory("data/shards");
    }

    mgr->file_capacity = 16;
    mgr->files = calloc(mgr->file_capacity, sizeof(file_shard_map_t));
    if (!mgr->files) return -1;

    pthread_mutex_init(&mgr->mutex, NULL);

    LOG_INFO("shard: Manager initialized for group '%s' (dir=%s)",
             mgr->group_id, mgr->shard_dir);
    return 0;
}

/*  Function: shard_manager_cleanup
    Description:
    Stops health monitoring, frees all file shard maps, and destroys the mutex.

    Parameters:
    - mgr: Pointer to the shard_manager_t structure.

    Steps:
    1. Stops the health monitor thread.
    2. Locks the mutex.
    3. Frees each file's shard descriptor array.
    4. Frees the file array.
    5. Unlocks and destroys the mutex.
*/
void shard_manager_cleanup(shard_manager_t* mgr) {
    if (!mgr) return;

    shard_health_stop(mgr);

    pthread_mutex_lock(&mgr->mutex);

    for (int i = 0; i < mgr->file_count; i++) {
        if (mgr->files[i].shards) {
            free(mgr->files[i].shards);
            mgr->files[i].shards = NULL;
        }
    }

    if (mgr->files) {
        free(mgr->files);
        mgr->files = NULL;
    }

    pthread_mutex_unlock(&mgr->mutex);
    pthread_mutex_destroy(&mgr->mutex);

    LOG_DEBUG("shard: Manager cleaned up");
}

/*  Function: shard_register_file
    Description:
    Registers a file for shard tracking, creating shard descriptors and a file-specific directory.

    Parameters:
    - mgr: Pointer to the shard_manager_t.
    - file_hash: SHA-256 hash of the file.
    - filename: Human-readable filename.
    - original_size: Original file size.
    - k: Data shard count.
    - n: Total shard count.
    - shard_size: Size of each shard.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Checks if the file is already registered.
    2. Grows the files array if capacity is reached.
    3. Initializes the file_shard_map_t with metadata.
    4. Allocates n shard_descriptor_t structures.
    5. Sets each descriptor's index, parity flag, and size.
    6. Creates a file-specific shard subdirectory.
    7. Increments file count.
*/
int shard_register_file(shard_manager_t* mgr,
                        const char* file_hash, const char* filename,
                        size_t original_size, int k, int n, size_t shard_size) {
    if (!mgr || !file_hash) return -1;

    pthread_mutex_lock(&mgr->mutex);

    for (int i = 0; i < mgr->file_count; i++) {
        if (memcmp(mgr->files[i].file_hash, file_hash, SHARD_HASH_SIZE) == 0) {
            pthread_mutex_unlock(&mgr->mutex);
            LOG_WARN("shard: File already registered");
            return 0;
        }
    }

    if (mgr->file_count >= mgr->file_capacity) {
        int new_cap = mgr->file_capacity * 2;
        file_shard_map_t* new_files = realloc(mgr->files,
                                               new_cap * sizeof(file_shard_map_t));
        if (!new_files) {
            pthread_mutex_unlock(&mgr->mutex);
            return -1;
        }
        memset(new_files + mgr->file_capacity, 0,
               (new_cap - mgr->file_capacity) * sizeof(file_shard_map_t));
        mgr->files = new_files;
        mgr->file_capacity = new_cap;
    }

    file_shard_map_t* map = &mgr->files[mgr->file_count];
    memset(map, 0, sizeof(file_shard_map_t));

    memcpy(map->file_hash, file_hash, SHARD_HASH_SIZE);
    if (filename) {
        strncpy(map->filename, filename, MAX_FILENAME_LENGTH - 1);
    }
    map->original_size = original_size;
    map->k = k;
    map->n = n;
    map->shard_size = shard_size;
    map->created_at = shard_get_timestamp_ms();

    map->shards = calloc(n, sizeof(shard_descriptor_t));
    if (!map->shards) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }

    for (int i = 0; i < n; i++) {
        map->shards[i].shard_index = i;
        map->shards[i].is_parity = (i >= k);
        map->shards[i].size = shard_size;
        map->shards[i].available = false;
        map->shards[i].redundancy = 0;
    }

    mgr->file_count++;

    char file_dir[600];
    char hash_hex[17];
    shard_bytes_to_hex((const uint8_t*)file_hash, 8, hash_hex, sizeof(hash_hex));
    snprintf(file_dir, sizeof(file_dir), "%s/%s", mgr->shard_dir, hash_hex);
    shard_ensure_directory(file_dir);

    pthread_mutex_unlock(&mgr->mutex);

    LOG_INFO("shard: Registered file '%s' (k=%d, n=%d, shard_size=%zu)",
             filename ? filename : "unknown", k, n, shard_size);
    return 0;
}

/*  Function: shard_unregister_file
    Description:
    Removes a file's shard tracking, freeing its descriptors.

    Parameters:
    - mgr: Pointer to the shard_manager_t.
    - file_hash: SHA-256 hash of the file to remove.

    Returns:
    - 0 on success, -1 if not found.

    Steps:
    1. Searches for the file by hash.
    2. Frees the shard descriptor array.
    3. Shifts remaining files left.
    4. Decrements file count.
*/
int shard_unregister_file(shard_manager_t* mgr, const char* file_hash) {
    if (!mgr || !file_hash) return -1;

    pthread_mutex_lock(&mgr->mutex);

    for (int i = 0; i < mgr->file_count; i++) {
        if (memcmp(mgr->files[i].file_hash, file_hash, SHARD_HASH_SIZE) == 0) {
            if (mgr->files[i].shards) {
                free(mgr->files[i].shards);
            }
            for (int j = i; j < mgr->file_count - 1; j++) {
                mgr->files[j] = mgr->files[j + 1];
            }
            mgr->file_count--;

            pthread_mutex_unlock(&mgr->mutex);
            LOG_INFO("shard: Unregistered file");
            return 0;
        }
    }

    pthread_mutex_unlock(&mgr->mutex);
    return -1;
}

/*  Function: shard_find_file
    Description:
    Finds a file's shard map by its hash.

    Parameters:
    - mgr: Pointer to the shard_manager_t.
    - file_hash: SHA-256 hash to search for.

    Returns:
    - Pointer to the file_shard_map_t, or NULL if not found.
*/
file_shard_map_t* shard_find_file(shard_manager_t* mgr, const char* file_hash) {
    if (!mgr || !file_hash) return NULL;

    for (int i = 0; i < mgr->file_count; i++) {
        if (memcmp(mgr->files[i].file_hash, file_hash, SHARD_HASH_SIZE) == 0) {
            return &mgr->files[i];
        }
    }
    return NULL;
}