#ifndef P2P_DHT_STORAGE_H
#define P2P_DHT_STORAGE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include "routing.h"

// ============================================
// DHT KEY-VALUE STORAGE
// ============================================
// Stores values published to the DHT.
// Each entry has a TTL and replication factor.

#define DHT_MAX_VALUE_SIZE     65536    // 64KB max value
#define DHT_MAX_ENTRIES        4096
#define DHT_DEFAULT_TTL_S      3600     // 1 hour
#define DHT_REPLICATION_FACTOR 3        // Store on k closest nodes
#define DHT_REPUBLISH_INTERVAL 3600     // Re-publish every hour

// ============================================
// STORAGE ENTRY
// ============================================
typedef struct {
    dht_node_id_t key;              // Key (160-bit hash)
    
    uint8_t* value;                 // Value data
    size_t value_len;
    
    dht_node_id_t publisher;        // Who published this
    
    uint64_t stored_at;             // When we stored it
    uint64_t expires_at;            // TTL expiration
    uint64_t last_republished;      // Last republish time
    
    int replication_count;          // How many nodes we've replicated to
    bool pinned;                    // Don't expire (local data)
    bool valid;                     // Slot in use
} dht_storage_entry_t;

// ============================================
// STORAGE
// ============================================
typedef struct {
    dht_storage_entry_t entries[DHT_MAX_ENTRIES];
    int entry_count;
    
    pthread_mutex_t mutex;
    
    // Stats
    uint64_t total_stores;
    uint64_t total_lookups;
    uint64_t total_evictions;
    uint64_t total_expirations;
} dht_storage_t;

// ============================================
// API
// ============================================

// Lifecycle
int dht_storage_init(dht_storage_t* store);
void dht_storage_cleanup(dht_storage_t* store);

// Store a key-value pair
// ttl_seconds: 0 = use default TTL
int dht_storage_put(dht_storage_t* store,
                    const dht_node_id_t* key,
                    const uint8_t* value, size_t value_len,
                    const dht_node_id_t* publisher,
                    uint32_t ttl_seconds);

// Retrieve a value by key
// value_out: buffer for value
// value_out_len: in = buffer size, out = actual value size
// Returns 0 if found, -1 if not found
int dht_storage_get(dht_storage_t* store,
                    const dht_node_id_t* key,
                    uint8_t* value_out, size_t* value_out_len);

// Check if key exists
bool dht_storage_has(const dht_storage_t* store, const dht_node_id_t* key);

// Remove a key
int dht_storage_remove(dht_storage_t* store, const dht_node_id_t* key);

// Pin a key (prevent expiration)
int dht_storage_pin(dht_storage_t* store, const dht_node_id_t* key);

// Expire old entries
// Returns number of entries expired
int dht_storage_expire(dht_storage_t* store);

// Get entries that need republishing
int dht_storage_get_republish(dht_storage_t* store,
                               dht_node_id_t* keys_out, int max_keys);

// Mark a key as republished
void dht_storage_mark_republished(dht_storage_t* store,
                                   const dht_node_id_t* key);

// ============================================
// UTILITY
// ============================================

void dht_storage_stats(const dht_storage_t* store,
                       int* entries, int* pinned,
                       uint64_t* total_bytes);
void dht_storage_print(const dht_storage_t* store);

#endif // P2P_DHT_STORAGE_H