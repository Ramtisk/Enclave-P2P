#ifndef P2P_SHARD_PRINT_H
#define P2P_SHARD_PRINT_H

#include "shard_types.h"

/*  ============================================
    SHARD PRINT API

    Note: Debug/display functions for shard maps and manager statistics.
    ============================================ */
void shard_print_file_map(const file_shard_map_t* map);
void shard_print_manager_stats(const shard_manager_t* mgr);

#endif