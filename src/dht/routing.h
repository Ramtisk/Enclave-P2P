#ifndef P2P_DHT_ROUTING_H
#define P2P_DHT_ROUTING_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>
#include <time.h>
#include "../common/config.h"

// ============================================
// KADEMLIA CONSTANTS
// ============================================
#define DHT_ID_BITS        160          // SHA-1 sized node IDs
#define DHT_ID_BYTES       (DHT_ID_BITS / 8)  // 20 bytes
#define DHT_K_BUCKET_SIZE  20           // Max nodes per bucket (k parameter)
#define DHT_ALPHA          3            // Concurrency parameter
#define DHT_BUCKET_COUNT   DHT_ID_BITS  // One bucket per bit

// Timeouts
#define DHT_NODE_TIMEOUT_MS    (15 * 60 * 1000)  // 15 minutes
#define DHT_REFRESH_INTERVAL_S 3600               // 1 hour
#define DHT_PING_TIMEOUT_MS    5000               // 5 second ping

// ============================================
// NODE ID
// ============================================
typedef struct {
    uint8_t bytes[DHT_ID_BYTES];
} dht_node_id_t;

// ============================================
// NODE INFO
// ============================================
typedef struct {
    dht_node_id_t id;
    char ip[46];
    uint16_t port;
    
    uint64_t last_seen;         // Last response timestamp
    uint64_t last_pinged;       // Last time we pinged this node
    int failed_pings;           // Consecutive failed pings
    bool is_good;               // Recently responded
} dht_node_t;

// ============================================
// K-BUCKET
// ============================================
// Each bucket holds nodes whose distance from us
// falls in a specific range: bucket i holds nodes
// where the XOR distance has bit i as the highest set bit.
typedef struct {
    dht_node_t nodes[DHT_K_BUCKET_SIZE];
    int count;
    uint64_t last_changed;      // When bucket was last modified
} k_bucket_t;

// ============================================
// ROUTING TABLE
// ============================================
typedef struct {
    dht_node_id_t self_id;      // Our own node ID
    k_bucket_t buckets[DHT_BUCKET_COUNT];
    
    int total_nodes;
    pthread_mutex_t mutex;
} routing_table_t;

// ============================================
// NODE ID OPERATIONS
// ============================================

// Generate random node ID
void dht_id_random(dht_node_id_t* id);

// Generate node ID from data (SHA-1 hash)
void dht_id_from_data(dht_node_id_t* id, const uint8_t* data, size_t len);

// XOR distance between two IDs
void dht_id_xor(dht_node_id_t* result, const dht_node_id_t* a, const dht_node_id_t* b);

// Compare two IDs (0 = equal, -1 = a<b, 1 = a>b)
int dht_id_compare(const dht_node_id_t* a, const dht_node_id_t* b);

// Check if two IDs are equal
bool dht_id_equal(const dht_node_id_t* a, const dht_node_id_t* b);

// Find highest set bit in distance (determines bucket index)
// Returns 0..159, or -1 if distance is zero
int dht_id_log2_distance(const dht_node_id_t* distance);

// Get bucket index for a target node (relative to our ID)
int dht_bucket_index(const routing_table_t* rt, const dht_node_id_t* target);

// Convert ID to hex string
void dht_id_to_hex(const dht_node_id_t* id, char* hex, size_t hex_len);

// Convert hex string to ID
int dht_id_from_hex(dht_node_id_t* id, const char* hex);

// ============================================
// ROUTING TABLE OPERATIONS
// ============================================

// Initialize routing table with our ID
int routing_table_init(routing_table_t* rt, const dht_node_id_t* self_id);

// Clean up
void routing_table_cleanup(routing_table_t* rt);

// Add or update a node
// Returns: 0 = added/updated, 1 = bucket full (node discarded), -1 = error
int routing_table_add(routing_table_t* rt, const dht_node_t* node);

// Remove a node
int routing_table_remove(routing_table_t* rt, const dht_node_id_t* id);

// Find the k closest nodes to a target
// results: output array (must have space for at least count entries)
// count: max results desired
// Returns: number of results found
int routing_table_find_closest(const routing_table_t* rt,
                               const dht_node_id_t* target,
                               dht_node_t* results, int count);

// Find a specific node by ID
dht_node_t* routing_table_find_node(routing_table_t* rt,
                                     const dht_node_id_t* id);

// Mark a node as having responded
void routing_table_mark_seen(routing_table_t* rt, const dht_node_id_t* id);

// Mark a node as failed (no response to ping)
void routing_table_mark_failed(routing_table_t* rt, const dht_node_id_t* id);

// Get nodes that need pinging (stale nodes)
int routing_table_get_stale(const routing_table_t* rt,
                             dht_node_t* stale_out, int max_count);

// Get buckets that need refreshing
int routing_table_get_refresh_buckets(const routing_table_t* rt,
                                      int* bucket_indices, int max_count);

// ============================================
// UTILITY
// ============================================

void routing_table_print(const routing_table_t* rt);
void routing_table_stats(const routing_table_t* rt,
                          int* total_nodes, int* good_nodes,
                          int* buckets_used);

#endif // P2P_DHT_ROUTING_H