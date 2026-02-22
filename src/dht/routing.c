#define _POSIX_C_SOURCE 200809L
#include "routing.h"
#include "../common/logging.h"
#include "../crypto/hashing.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

// SHA-1 simplified for node ID generation
// Using SHA-256 from hashing.h, truncated to 20 bytes
extern void sha256_hash(const uint8_t* data, size_t len, uint8_t* hash_out);

// ============================================
// HELPERS
// ============================================

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// ============================================
// NODE ID OPERATIONS
// ============================================

void dht_id_random(dht_node_id_t* id) {
    if (!id) return;
    
    // Use /dev/urandom for randomness
    FILE* f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t rd = fread(id->bytes, 1, DHT_ID_BYTES, f);
        fclose(f);
        if (rd == DHT_ID_BYTES) return;
    }
    
    // Fallback
    srand((unsigned)time(NULL) ^ (unsigned)(uintptr_t)id);
    for (int i = 0; i < DHT_ID_BYTES; i++) {
        id->bytes[i] = (uint8_t)(rand() & 0xFF);
    }
}

void dht_id_from_data(dht_node_id_t* id, const uint8_t* data, size_t len) {
    if (!id || !data) return;
    
    uint8_t hash[32];
    sha256_hash(data, len, hash);
    // Truncate SHA-256 to 160 bits (20 bytes)
    memcpy(id->bytes, hash, DHT_ID_BYTES);
}

void dht_id_xor(dht_node_id_t* result, const dht_node_id_t* a, const dht_node_id_t* b) {
    if (!result || !a || !b) return;
    for (int i = 0; i < DHT_ID_BYTES; i++) {
        result->bytes[i] = a->bytes[i] ^ b->bytes[i];
    }
}

int dht_id_compare(const dht_node_id_t* a, const dht_node_id_t* b) {
    if (!a || !b) return 0;
    return memcmp(a->bytes, b->bytes, DHT_ID_BYTES);
}

bool dht_id_equal(const dht_node_id_t* a, const dht_node_id_t* b) {
    if (!a || !b) return false;
    return memcmp(a->bytes, b->bytes, DHT_ID_BYTES) == 0;
}

int dht_id_log2_distance(const dht_node_id_t* distance) {
    // Find the highest set bit
    for (int i = 0; i < DHT_ID_BYTES; i++) {
        if (distance->bytes[i] == 0) continue;
        
        uint8_t byte = distance->bytes[i];
        int bit = 7;
        while (bit >= 0 && !(byte & (1 << bit))) {
            bit--;
        }
        
        return (DHT_ID_BYTES - 1 - i) * 8 + bit;
    }
    return -1; // Distance is zero (same node)
}

int dht_bucket_index(const routing_table_t* rt, const dht_node_id_t* target) {
    if (!rt || !target) return -1;
    
    dht_node_id_t distance;
    dht_id_xor(&distance, &rt->self_id, target);
    
    int idx = dht_id_log2_distance(&distance);
    if (idx < 0) return -1; // Same as self
    return idx;
}

void dht_id_to_hex(const dht_node_id_t* id, char* hex, size_t hex_len) {
    if (!id || !hex || hex_len < DHT_ID_BYTES * 2 + 1) return;
    for (int i = 0; i < DHT_ID_BYTES; i++) {
        snprintf(hex + i * 2, 3, "%02x", id->bytes[i]);
    }
    hex[DHT_ID_BYTES * 2] = '\0';
}

int dht_id_from_hex(dht_node_id_t* id, const char* hex) {
    if (!id || !hex) return -1;
    
    size_t hex_len = strlen(hex);
    if (hex_len < DHT_ID_BYTES * 2) return -1;
    
    for (int i = 0; i < DHT_ID_BYTES; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id->bytes[i] = (uint8_t)byte;
    }
    return 0;
}

// ============================================
// ROUTING TABLE
// ============================================

int routing_table_init(routing_table_t* rt, const dht_node_id_t* self_id) {
    if (!rt || !self_id) return -1;
    
    memset(rt, 0, sizeof(routing_table_t));
    memcpy(&rt->self_id, self_id, sizeof(dht_node_id_t));
    
    uint64_t now = get_timestamp_ms();
    for (int i = 0; i < DHT_BUCKET_COUNT; i++) {
        rt->buckets[i].count = 0;
        rt->buckets[i].last_changed = now;
    }
    
    pthread_mutex_init(&rt->mutex, NULL);
    
    char hex[DHT_ID_BYTES * 2 + 1];
    dht_id_to_hex(self_id, hex, sizeof(hex));
    LOG_INFO("dht/routing: Table initialized (self=%s)", hex);
    
    return 0;
}

void routing_table_cleanup(routing_table_t* rt) {
    if (!rt) return;
    pthread_mutex_destroy(&rt->mutex);
    LOG_DEBUG("dht/routing: Table cleaned up");
}

int routing_table_add(routing_table_t* rt, const dht_node_t* node) {
    if (!rt || !node) return -1;
    
    // Don't add ourselves
    if (dht_id_equal(&rt->self_id, &node->id)) return -1;
    
    pthread_mutex_lock(&rt->mutex);
    
    int bucket_idx = dht_bucket_index(rt, &node->id);
    if (bucket_idx < 0 || bucket_idx >= DHT_BUCKET_COUNT) {
        pthread_mutex_unlock(&rt->mutex);
        return -1;
    }
    
    k_bucket_t* bucket = &rt->buckets[bucket_idx];
    
    // Check if node already exists — update it
    for (int i = 0; i < bucket->count; i++) {
        if (dht_id_equal(&bucket->nodes[i].id, &node->id)) {
            // Move to tail (most recently seen)
            dht_node_t existing = bucket->nodes[i];
            existing.last_seen = get_timestamp_ms();
            existing.is_good = true;
            existing.failed_pings = 0;
            
            // Update IP/port in case they changed
            strncpy(existing.ip, node->ip, sizeof(existing.ip) - 1);
            existing.port = node->port;
            
            // Shift and place at end
            for (int j = i; j < bucket->count - 1; j++) {
                bucket->nodes[j] = bucket->nodes[j + 1];
            }
            bucket->nodes[bucket->count - 1] = existing;
            bucket->last_changed = get_timestamp_ms();
            
            pthread_mutex_unlock(&rt->mutex);
            return 0;
        }
    }
    
    // Node not in bucket — try to add
    if (bucket->count < DHT_K_BUCKET_SIZE) {
        // Bucket has space
        dht_node_t new_node = *node;
        new_node.last_seen = get_timestamp_ms();
        new_node.is_good = true;
        new_node.failed_pings = 0;
        
        bucket->nodes[bucket->count] = new_node;
        bucket->count++;
        bucket->last_changed = get_timestamp_ms();
        rt->total_nodes++;
        
        pthread_mutex_unlock(&rt->mutex);
        return 0;
    }
    
    // Bucket full — check if head (least recently seen) is stale
    dht_node_t* head = &bucket->nodes[0];
    uint64_t now = get_timestamp_ms();
    
    if (now - head->last_seen > DHT_NODE_TIMEOUT_MS || head->failed_pings >= 3) {
        // Replace stale node
        // Shift all down and put new node at tail
        for (int j = 0; j < bucket->count - 1; j++) {
            bucket->nodes[j] = bucket->nodes[j + 1];
        }
        
        dht_node_t new_node = *node;
        new_node.last_seen = now;
        new_node.is_good = true;
        new_node.failed_pings = 0;
        bucket->nodes[bucket->count - 1] = new_node;
        bucket->last_changed = now;
        
        pthread_mutex_unlock(&rt->mutex);
        return 0;
    }
    
    // Bucket full, head is still good — discard new node
    pthread_mutex_unlock(&rt->mutex);
    return 1;
}

int routing_table_remove(routing_table_t* rt, const dht_node_id_t* id) {
    if (!rt || !id) return -1;
    
    pthread_mutex_lock(&rt->mutex);
    
    int bucket_idx = dht_bucket_index(rt, id);
    if (bucket_idx < 0) {
        pthread_mutex_unlock(&rt->mutex);
        return -1;
    }
    
    k_bucket_t* bucket = &rt->buckets[bucket_idx];
    
    for (int i = 0; i < bucket->count; i++) {
        if (dht_id_equal(&bucket->nodes[i].id, id)) {
            for (int j = i; j < bucket->count - 1; j++) {
                bucket->nodes[j] = bucket->nodes[j + 1];
            }
            bucket->count--;
            rt->total_nodes--;
            
            pthread_mutex_unlock(&rt->mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&rt->mutex);
    return -1;
}

// ============================================
// FIND CLOSEST
// ============================================

// Helper for sorting by XOR distance
typedef struct {
    dht_node_t node;
    dht_node_id_t distance;
} node_distance_t;

static int compare_node_distance(const void* a, const void* b) {
    const node_distance_t* na = (const node_distance_t*)a;
    const node_distance_t* nb = (const node_distance_t*)b;
    return memcmp(na->distance.bytes, nb->distance.bytes, DHT_ID_BYTES);
}

int routing_table_find_closest(const routing_table_t* rt,
                               const dht_node_id_t* target,
                               dht_node_t* results, int count) {
    if (!rt || !target || !results || count <= 0) return 0;
    
    // Collect all nodes with their distances
    node_distance_t* all = malloc(rt->total_nodes * sizeof(node_distance_t));
    if (!all && rt->total_nodes > 0) return 0;
    
    int total = 0;
    for (int b = 0; b < DHT_BUCKET_COUNT; b++) {
        const k_bucket_t* bucket = &rt->buckets[b];
        for (int i = 0; i < bucket->count; i++) {
            all[total].node = bucket->nodes[i];
            dht_id_xor(&all[total].distance, target, &bucket->nodes[i].id);
            total++;
        }
    }
    
    // Sort by distance
    if (total > 0) {
        qsort(all, total, sizeof(node_distance_t), compare_node_distance);
    }
    
    // Return top `count` results
    int result_count = (total < count) ? total : count;
    for (int i = 0; i < result_count; i++) {
        results[i] = all[i].node;
    }
    
    free(all);
    return result_count;
}

dht_node_t* routing_table_find_node(routing_table_t* rt,
                                     const dht_node_id_t* id) {
    if (!rt || !id) return NULL;
    
    int bucket_idx = dht_bucket_index(rt, id);
    if (bucket_idx < 0) return NULL;
    
    k_bucket_t* bucket = &rt->buckets[bucket_idx];
    for (int i = 0; i < bucket->count; i++) {
        if (dht_id_equal(&bucket->nodes[i].id, id)) {
            return &bucket->nodes[i];
        }
    }
    return NULL;
}

// ============================================
// LIVENESS
// ============================================

void routing_table_mark_seen(routing_table_t* rt, const dht_node_id_t* id) {
    if (!rt || !id) return;
    
    pthread_mutex_lock(&rt->mutex);
    
    dht_node_t* node = routing_table_find_node(rt, id);
    if (node) {
        node->last_seen = get_timestamp_ms();
        node->is_good = true;
        node->failed_pings = 0;
    }
    
    pthread_mutex_unlock(&rt->mutex);
}

void routing_table_mark_failed(routing_table_t* rt, const dht_node_id_t* id) {
    if (!rt || !id) return;
    
    pthread_mutex_lock(&rt->mutex);
    
    dht_node_t* node = routing_table_find_node(rt, id);
    if (node) {
        node->failed_pings++;
        if (node->failed_pings >= 3) {
            node->is_good = false;
        }
    }
    
    pthread_mutex_unlock(&rt->mutex);
}

int routing_table_get_stale(const routing_table_t* rt,
                             dht_node_t* stale_out, int max_count) {
    if (!rt || !stale_out) return 0;
    
    uint64_t now = get_timestamp_ms();
    int count = 0;
    
    for (int b = 0; b < DHT_BUCKET_COUNT && count < max_count; b++) {
        const k_bucket_t* bucket = &rt->buckets[b];
        for (int i = 0; i < bucket->count && count < max_count; i++) {
            if (now - bucket->nodes[i].last_seen > DHT_NODE_TIMEOUT_MS) {
                stale_out[count++] = bucket->nodes[i];
            }
        }
    }
    
    return count;
}

int routing_table_get_refresh_buckets(const routing_table_t* rt,
                                      int* bucket_indices, int max_count) {
    if (!rt || !bucket_indices) return 0;
    
    uint64_t now = get_timestamp_ms();
    uint64_t refresh_ms = (uint64_t)DHT_REFRESH_INTERVAL_S * 1000;
    int count = 0;
    
    for (int b = 0; b < DHT_BUCKET_COUNT && count < max_count; b++) {
        if (rt->buckets[b].count > 0 &&
            now - rt->buckets[b].last_changed > refresh_ms) {
            bucket_indices[count++] = b;
        }
    }
    
    return count;
}

// ============================================
// UTILITY
// ============================================

void routing_table_stats(const routing_table_t* rt,
                          int* total_nodes, int* good_nodes,
                          int* buckets_used) {
    if (!rt) return;
    
    int total = 0, good = 0, used = 0;
    
    for (int b = 0; b < DHT_BUCKET_COUNT; b++) {
        const k_bucket_t* bucket = &rt->buckets[b];
        if (bucket->count > 0) used++;
        total += bucket->count;
        
        for (int i = 0; i < bucket->count; i++) {
            if (bucket->nodes[i].is_good) good++;
        }
    }
    
    if (total_nodes) *total_nodes = total;
    if (good_nodes) *good_nodes = good;
    if (buckets_used) *buckets_used = used;
}

void routing_table_print(const routing_table_t* rt) {
    if (!rt) return;
    
    char hex[DHT_ID_BYTES * 2 + 1];
    dht_id_to_hex(&rt->self_id, hex, sizeof(hex));
    
    int total, good, used;
    routing_table_stats(rt, &total, &good, &used);
    
    LOG_INFO("╔══════════════════════════════════════════════╗");
    LOG_INFO("║          KADEMLIA ROUTING TABLE              ║");
    LOG_INFO("╠══════════════════════════════════════════════╣");
    LOG_INFO("║  Self:    %.40s ║", hex);
    LOG_INFO("║  Nodes:   %d total, %d good                   ║", total, good);
    LOG_INFO("║  Buckets: %d/%d used                          ║", used, DHT_BUCKET_COUNT);
    LOG_INFO("╠══════════════════════════════════════════════╣");
    
    for (int b = 0; b < DHT_BUCKET_COUNT; b++) {
        if (rt->buckets[b].count > 0) {
            LOG_INFO("║  Bucket %3d: %d nodes                        ║",
                     b, rt->buckets[b].count);
        }
    }
    LOG_INFO("╚══════════════════════════════════════════════╝");
}