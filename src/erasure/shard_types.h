#ifndef P2P_SHARD_TYPES_H
#define P2P_SHARD_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include "../common/config.h"

/*  ============================================
    SHARD DISTRIBUTION CONSTANTS
    ============================================ */
#define SHARD_HASH_SIZE       32
#define MAX_SHARD_REPLICAS    5
#define SHARD_HEALTH_INTERVAL 30
#define SHARD_CRITICAL_LEVEL  1

/*  ============================================
    SHARD HOLDER

    Note: A single peer that holds a copy of a shard.
    ============================================ */
typedef struct {
    char peer_id[MAX_ID_LENGTH];
    char ip[46];
    uint16_t port;
    bool alive;
    uint64_t last_seen;
} shard_holder_t;

/*  ============================================
    SHARD DESCRIPTOR

    Note: Describes a single shard within a file's encoded set.
    Tracks which peers hold copies and overall availability.
    ============================================ */
typedef struct {
    int shard_index;
    uint8_t hash[SHARD_HASH_SIZE];
    size_t size;
    bool is_parity;
    shard_holder_t holders[MAX_SHARD_REPLICAS];
    int holder_count;
    bool available;
    int redundancy;
} shard_descriptor_t;

/*  ============================================
    FILE SHARD MAP

    Note: Tracks all shards for a single file.
    Contains shard descriptors, health summary, and file metadata.
    ============================================ */
typedef struct {
    char file_hash[SHARD_HASH_SIZE];
    char filename[MAX_FILENAME_LENGTH];
    size_t original_size;
    int k;
    int n;
    size_t shard_size;
    shard_descriptor_t* shards;
    int shards_available;
    int shards_critical;
    int min_redundancy;
    bool reconstructable;
    uint64_t created_at;
    uint64_t last_health_check;
} file_shard_map_t;

/*  ============================================
    SHARD MANAGER

    Note: Manages shard maps for all files in a group.
    Contains file array, health monitoring thread, callbacks, and statistics.
    ============================================ */
typedef struct {
    file_shard_map_t* files;
    int file_count;
    int file_capacity;
    char group_id[MAX_ID_LENGTH];
    char shard_dir[512];
    bool health_running;
    pthread_t health_thread;
    pthread_mutex_t mutex;
    void (*on_shard_critical)(const char* file_hash, int shard_index,
                              int redundancy, void* user_data);
    void (*on_file_unrecoverable)(const char* file_hash, void* user_data);
    void* callback_data;
    uint64_t total_shards_stored;
    uint64_t total_bytes_stored;
} shard_manager_t;

/*  ============================================
    ASSIGNMENT STRATEGY

    Note: Strategy for distributing shards across peers.
    ============================================ */
typedef enum {
    ASSIGN_ROUND_ROBIN = 0,
    ASSIGN_RANDOM,
    ASSIGN_CAPACITY_BASED
} shard_assign_strategy_t;

/*  ============================================
    PEER STORAGE INFO

    Note: Describes a peer's storage capabilities and status.
    Used during shard assignment decisions.
    ============================================ */
typedef struct {
    char peer_id[MAX_ID_LENGTH];
    char ip[46];
    uint16_t port;
    uint64_t capacity_bytes;
    uint64_t used_bytes;
    int shard_count;
    bool online;
} peer_storage_info_t;

#endif