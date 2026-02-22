#define _POSIX_C_SOURCE 200809L
#include "storage.h"
#include "../common/logging.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

// ============================================
// HELPERS
// ============================================

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static dht_storage_entry_t* find_entry(dht_storage_t* store,
                                        const dht_node_id_t* key) {
    for (int i = 0; i < DHT_MAX_ENTRIES; i++) {
        if (store->entries[i].valid &&
            dht_id_equal(&store->entries[i].key, key)) {
            return &store->entries[i];
        }
    }
    return NULL;
}

static dht_storage_entry_t* find_free_slot(dht_storage_t* store) {
    // Find empty slot
    for (int i = 0; i < DHT_MAX_ENTRIES; i++) {
        if (!store->entries[i].valid) {
            return &store->entries[i];
        }
    }
    
    // No empty slot — evict oldest non-pinned entry
    dht_storage_entry_t* oldest = NULL;
    for (int i = 0; i < DHT_MAX_ENTRIES; i++) {
        if (store->entries[i].pinned) continue;
        if (!oldest || store->entries[i].stored_at < oldest->stored_at) {
            oldest = &store->entries[i];
        }
    }
    
    if (oldest) {
        if (oldest->value) {
            free(oldest->value);
            oldest->value = NULL;
        }
        oldest->valid = false;
        store->total_evictions++;
    }
    
    return oldest;
}

// ============================================
// LIFECYCLE
// ============================================

int dht_storage_init(dht_storage_t* store) {
    if (!store) return -1;
    
    memset(store, 0, sizeof(dht_storage_t));
    pthread_mutex_init(&store->mutex, NULL);
    
    LOG_INFO("dht/storage: Initialized (max_entries=%d, max_value=%d bytes)",
             DHT_MAX_ENTRIES, DHT_MAX_VALUE_SIZE);
    return 0;
}

void dht_storage_cleanup(dht_storage_t* store) {
    if (!store) return;
    
    pthread_mutex_lock(&store->mutex);
    
    for (int i = 0; i < DHT_MAX_ENTRIES; i++) {
        if (store->entries[i].valid && store->entries[i].value) {
            free(store->entries[i].value);
            store->entries[i].value = NULL;
        }
    }
    
    pthread_mutex_unlock(&store->mutex);
    pthread_mutex_destroy(&store->mutex);
    
    LOG_DEBUG("dht/storage: Cleaned up");
}

// ============================================
// STORE / RETRIEVE
// ============================================

int dht_storage_put(dht_storage_t* store,
                    const dht_node_id_t* key,
                    const uint8_t* value, size_t value_len,
                    const dht_node_id_t* publisher,
                    uint32_t ttl_seconds) {
    if (!store || !key || !value || value_len == 0) return -1;
    if (value_len > DHT_MAX_VALUE_SIZE) {
        LOG_ERROR("dht/storage: Value too large (%zu > %d)", value_len, DHT_MAX_VALUE_SIZE);
        return -1;
    }
    
    if (ttl_seconds == 0) ttl_seconds = DHT_DEFAULT_TTL_S;
    
    pthread_mutex_lock(&store->mutex);
    
    uint64_t now = get_timestamp_ms();
    
    // Check if key already exists — update
    dht_storage_entry_t* existing = find_entry(store, key);
    if (existing) {
        // Replace value
        uint8_t* new_val = realloc(existing->value, value_len);
        if (!new_val) {
            pthread_mutex_unlock(&store->mutex);
            return -1;
        }
        existing->value = new_val;
        memcpy(existing->value, value, value_len);
        existing->value_len = value_len;
        existing->stored_at = now;
        existing->expires_at = now + (uint64_t)ttl_seconds * 1000;
        if (publisher) existing->publisher = *publisher;
        
        store->total_stores++;
        pthread_mutex_unlock(&store->mutex);
        return 0;
    }
    
    // New entry
    dht_storage_entry_t* slot = find_free_slot(store);
    if (!slot) {
        pthread_mutex_unlock(&store->mutex);
        LOG_ERROR("dht/storage: No free slots (all %d entries pinned?)", DHT_MAX_ENTRIES);
        return -1;
    }
    
    memset(slot, 0, sizeof(dht_storage_entry_t));
    slot->key = *key;
    slot->value = malloc(value_len);
    if (!slot->value) {
        pthread_mutex_unlock(&store->mutex);
        return -1;
    }
    memcpy(slot->value, value, value_len);
    slot->value_len = value_len;
    
    if (publisher) slot->publisher = *publisher;
    slot->stored_at = now;
    slot->expires_at = now + (uint64_t)ttl_seconds * 1000;
    slot->last_republished = now;
    slot->valid = true;
    
    store->entry_count++;
    store->total_stores++;
    
    pthread_mutex_unlock(&store->mutex);
    
    LOG_TRACE("dht/storage: Stored %zu bytes (TTL=%us)", value_len, ttl_seconds);
    return 0;
}

int dht_storage_get(dht_storage_t* store,
                    const dht_node_id_t* key,
                    uint8_t* value_out, size_t* value_out_len) {
    if (!store || !key || !value_out || !value_out_len) return -1;
    
    pthread_mutex_lock(&store->mutex);
    store->total_lookups++;
    
    dht_storage_entry_t* entry = find_entry(store, key);
    if (!entry) {
        pthread_mutex_unlock(&store->mutex);
        return -1;
    }
    
    // Check TTL
    uint64_t now = get_timestamp_ms();
    if (!entry->pinned && now > entry->expires_at) {
        // Expired
        free(entry->value);
        entry->value = NULL;
        entry->valid = false;
        store->entry_count--;
        store->total_expirations++;
        
        pthread_mutex_unlock(&store->mutex);
        return -1;
    }
    
    size_t copy_len = entry->value_len;
    if (copy_len > *value_out_len) copy_len = *value_out_len;
    
    memcpy(value_out, entry->value, copy_len);
    *value_out_len = entry->value_len;
    
    pthread_mutex_unlock(&store->mutex);
    return 0;
}

bool dht_storage_has(const dht_storage_t* store, const dht_node_id_t* key) {
    if (!store || !key) return false;
    
    for (int i = 0; i < DHT_MAX_ENTRIES; i++) {
        if (store->entries[i].valid &&
            dht_id_equal(&store->entries[i].key, key)) {
            return true;
        }
    }
    return false;
}

int dht_storage_remove(dht_storage_t* store, const dht_node_id_t* key) {
    if (!store || !key) return -1;
    
    pthread_mutex_lock(&store->mutex);
    
    dht_storage_entry_t* entry = find_entry(store, key);
    if (!entry) {
        pthread_mutex_unlock(&store->mutex);
        return -1;
    }
    
    if (entry->value) {
        free(entry->value);
        entry->value = NULL;
    }
    entry->valid = false;
    store->entry_count--;
    
    pthread_mutex_unlock(&store->mutex);
    return 0;
}

int dht_storage_pin(dht_storage_t* store, const dht_node_id_t* key) {
    if (!store || !key) return -1;
    
    pthread_mutex_lock(&store->mutex);
    
    dht_storage_entry_t* entry = find_entry(store, key);
    if (!entry) {
        pthread_mutex_unlock(&store->mutex);
        return -1;
    }
    
    entry->pinned = true;
    
    pthread_mutex_unlock(&store->mutex);
    return 0;
}

int dht_storage_expire(dht_storage_t* store) {
    if (!store) return 0;
    
    pthread_mutex_lock(&store->mutex);
    
    uint64_t now = get_timestamp_ms();
    int expired = 0;
    
    for (int i = 0; i < DHT_MAX_ENTRIES; i++) {
        dht_storage_entry_t* e = &store->entries[i];
        if (e->valid && !e->pinned && now > e->expires_at) {
            if (e->value) {
                free(e->value);
                e->value = NULL;
            }
            e->valid = false;
            store->entry_count--;
            store->total_expirations++;
            expired++;
        }
    }
    
    pthread_mutex_unlock(&store->mutex);
    
    if (expired > 0) {
        LOG_DEBUG("dht/storage: Expired %d entries", expired);
    }
    return expired;
}

int dht_storage_get_republish(dht_storage_t* store,
                               dht_node_id_t* keys_out, int max_keys) {
    if (!store || !keys_out) return 0;
    
    pthread_mutex_lock(&store->mutex);
    
    uint64_t now = get_timestamp_ms();
    uint64_t threshold = (uint64_t)DHT_REPUBLISH_INTERVAL * 1000;
    int count = 0;
    
    for (int i = 0; i < DHT_MAX_ENTRIES && count < max_keys; i++) {
        dht_storage_entry_t* e = &store->entries[i];
        if (e->valid && now - e->last_republished > threshold) {
            keys_out[count++] = e->key;
        }
    }
    
    pthread_mutex_unlock(&store->mutex);
    return count;
}

void dht_storage_mark_republished(dht_storage_t* store,
                                   const dht_node_id_t* key) {
    if (!store || !key) return;
    
    pthread_mutex_lock(&store->mutex);
    
    dht_storage_entry_t* entry = find_entry(store, key);
    if (entry) {
        entry->last_republished = get_timestamp_ms();
    }
    
    pthread_mutex_unlock(&store->mutex);
}

// ============================================
// UTILITY
// ============================================

void dht_storage_stats(const dht_storage_t* store,
                       int* entries, int* pinned,
                       uint64_t* total_bytes) {
    if (!store) return;
    
    int e = 0, p = 0;
    uint64_t bytes = 0;
    
    for (int i = 0; i < DHT_MAX_ENTRIES; i++) {
        if (store->entries[i].valid) {
            e++;
            bytes += store->entries[i].value_len;
            if (store->entries[i].pinned) p++;
        }
    }
    
    if (entries) *entries = e;
    if (pinned) *pinned = p;
    if (total_bytes) *total_bytes = bytes;
}

void dht_storage_print(const dht_storage_t* store) {
    if (!store) return;
    
    int entries, pinned;
    uint64_t bytes;
    dht_storage_stats(store, &entries, &pinned, &bytes);
    
    LOG_INFO("╔══════════════════════════════════════╗");
    LOG_INFO("║          DHT STORAGE                 ║");
    LOG_INFO("╠══════════════════════════════════════╣");
    LOG_INFO("║  Entries:       %d/%d %-14s ║", entries, DHT_MAX_ENTRIES, "");
    LOG_INFO("║  Pinned:        %-20d ║", pinned);
    LOG_INFO("║  Total bytes:   %-20lu ║", (unsigned long)bytes);
    LOG_INFO("║  Total stores:  %-20lu ║", (unsigned long)store->total_stores);
    LOG_INFO("║  Total lookups: %-20lu ║", (unsigned long)store->total_lookups);
    LOG_INFO("║  Evictions:     %-20lu ║", (unsigned long)store->total_evictions);
    LOG_INFO("║  Expirations:   %-20lu ║", (unsigned long)store->total_expirations);
    LOG_INFO("╚══════════════════════════════════════╝");
}