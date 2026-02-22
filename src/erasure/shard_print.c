#include "shard_print.h"
#include "shard_helpers.h"
#include "../common/logging.h"

#include <stdio.h>

/*  Function: shard_print_file_map
    Description:
    Prints a formatted table of a file's shard map including all descriptors.

    Parameters:
    - map: Pointer to the file_shard_map_t.

    Steps:
    1. Converts the file hash prefix to hex.
    2. Prints file metadata (name, hash, size, k/n, shard size).
    3. Prints health summary (available, critical, reconstructable).
    4. Prints each shard descriptor with type, status, holders, and redundancy.
*/
void shard_print_file_map(const file_shard_map_t* map) {
    if (!map) return;

    char hash_hex[17];
    shard_bytes_to_hex((const uint8_t*)map->file_hash, 8, hash_hex, sizeof(hash_hex));

    LOG_INFO("╔══════════════════════════════════════╗");
    LOG_INFO("║          SHARD MAP                   ║");
    LOG_INFO("╠══════════════════════════════════════╣");
    LOG_INFO("║  File:       %-23s ║", map->filename);
    LOG_INFO("║  Hash:       %-23s ║", hash_hex);
    LOG_INFO("║  Size:       %-20zu B ║", map->original_size);
    LOG_INFO("║  k/n:        %d/%d %-18s ║", map->k, map->n, "");
    LOG_INFO("║  Shard size: %-20zu B ║", map->shard_size);
    LOG_INFO("║  Available:  %d/%-21d ║", map->shards_available, map->n);
    LOG_INFO("║  Critical:   %-23d ║", map->shards_critical);
    LOG_INFO("║  Rebuild OK: %-23s ║", map->reconstructable ? "YES" : "NO");
    LOG_INFO("╠══════════════════════════════════════╣");

    for (int i = 0; i < map->n; i++) {
        const shard_descriptor_t* sd = &map->shards[i];
        LOG_INFO("║  %s%d: %s (holders=%d, redundancy=%d)    ║",
                 sd->is_parity ? "P" : "D", i,
                 sd->available ? "✓" : "✗",
                 sd->holder_count, sd->redundancy);
    }
    LOG_INFO("╚══════════════════════════════════════╝");
}

/*  Function: shard_print_manager_stats
    Description:
    Prints summary statistics for the shard manager.

    Parameters:
    - mgr: Pointer to the shard_manager_t.

    Steps:
    1. Logs group ID, file count, total stored shards, and total bytes.
*/
void shard_print_manager_stats(const shard_manager_t* mgr) {
    if (!mgr) return;

    LOG_INFO("Shard Manager: group=%s, files=%d, stored=%lu shards (%lu bytes)",
             mgr->group_id, mgr->file_count,
             (unsigned long)mgr->total_shards_stored,
             (unsigned long)mgr->total_bytes_stored);
}