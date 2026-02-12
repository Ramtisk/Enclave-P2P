#ifndef P2P_TRANSFER_STRATEGY_H
#define P2P_TRANSFER_STRATEGY_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "../chunking.h"
#include "../../common/config.h"

// ============================================
// STRATEGY TYPES
// ============================================
typedef enum {
    STRATEGY_SEQUENTIAL = 0,    // Linear chunk order
    STRATEGY_RANDOM,            // Random chunk selection
    STRATEGY_RAREST_FIRST       // BitTorrent-style rarest first
} strategy_type_t;

// ============================================
// PEER AVAILABILITY MAP
// ============================================
typedef struct {
    char peer_id[MAX_ID_LENGTH];
    char ip[46];
    uint16_t port;
    int socket_fd;

    // Which chunks this peer has (bitfield)
    bool* chunk_bitmap;
    uint32_t chunk_count;
    uint32_t available_chunks;  // Count of chunks this peer has

    // Performance metrics
    double bandwidth_bps;       // Measured bytes/sec
    double avg_latency_ms;      // Average round-trip latency
    uint32_t chunks_served;     // How many chunks downloaded from this peer
    uint32_t failures;          // Failed chunk requests
    uint64_t last_activity;     // Timestamp of last successful transfer

    bool connected;
    bool active;                // Currently downloading from this peer
} peer_source_t;

// ============================================
// CHUNK AVAILABILITY TRACKER
// ============================================
typedef struct {
    uint32_t chunk_index;
    uint32_t availability;      // How many peers have this chunk
    bool downloaded;            // Already got this chunk
    bool in_progress;           // Currently being downloaded
    char assigned_peer[MAX_ID_LENGTH]; // Peer assigned to download this
    uint64_t request_time;      // When the request was sent
    uint32_t retry_count;       // How many times we retried
} chunk_tracker_t;

// ============================================
// STRATEGY CONTEXT
// ============================================
typedef struct {
    strategy_type_t type;
    
    // Chunk tracking
    chunk_tracker_t* chunks;
    uint32_t total_chunks;
    uint32_t completed_chunks;
    uint32_t in_progress_chunks;
    
    // Peer sources
    peer_source_t peers[MAX_GROUP_MEMBERS];
    int peer_count;
    
    // Random state (for STRATEGY_RANDOM)
    uint32_t random_seed;
    
    // Thread safety
    pthread_mutex_t mutex;
    
    // Statistics
    uint64_t started_at;
    uint64_t bytes_downloaded;
    double overall_rate_bps;
} strategy_context_t;

// ============================================
// API
// ============================================

// Lifecycle
int strategy_init(strategy_context_t* ctx, strategy_type_t type, uint32_t chunk_count);
void strategy_cleanup(strategy_context_t* ctx);

// Peer management
int strategy_add_peer(strategy_context_t* ctx, const char* peer_id,
                      const char* ip, uint16_t port);
int strategy_remove_peer(strategy_context_t* ctx, const char* peer_id);
int strategy_set_peer_bitmap(strategy_context_t* ctx, const char* peer_id,
                             const bool* bitmap, uint32_t count);
void strategy_update_peer_metrics(strategy_context_t* ctx, const char* peer_id,
                                   double bandwidth, double latency);
void strategy_record_peer_failure(strategy_context_t* ctx, const char* peer_id);

// Chunk selection — the core strategy function
// Returns chunk index to download next, -1 if none available
int32_t strategy_select_next_chunk(strategy_context_t* ctx, const char* peer_id);

// Mark chunk status
void strategy_mark_downloaded(strategy_context_t* ctx, uint32_t chunk_index);
void strategy_mark_in_progress(strategy_context_t* ctx, uint32_t chunk_index,
                                const char* peer_id);
void strategy_mark_failed(strategy_context_t* ctx, uint32_t chunk_index);

// Query
bool strategy_is_complete(const strategy_context_t* ctx);
float strategy_get_progress(const strategy_context_t* ctx);
void strategy_get_stats(const strategy_context_t* ctx, uint32_t* completed,
                        uint32_t* in_progress, uint32_t* remaining);

// Helpers
const char* strategy_type_string(strategy_type_t type);

#endif // P2P_TRANSFER_STRATEGY_H