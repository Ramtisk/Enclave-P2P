#include "strategy.h"
#include "../../common/logging.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

// ============================================
// EXTERNAL STRATEGY FUNCTIONS
// ============================================
// Defined in sequential.c, random.c, rarest_first.c
extern int32_t sequential_select_for_peer(strategy_context_t* ctx, const char* peer_id);
extern int32_t random_select(strategy_context_t* ctx, const char* peer_id);
extern int32_t rarest_first_select(strategy_context_t* ctx, const char* peer_id);

// ============================================
// HELPERS
// ============================================

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

const char* strategy_type_string(strategy_type_t type) {
    switch (type) {
        case STRATEGY_SEQUENTIAL:   return "Sequential";
        case STRATEGY_RANDOM:       return "Random";
        case STRATEGY_RAREST_FIRST: return "Rarest-First";
        default:                    return "Unknown";
    }
}

// ============================================
// LIFECYCLE
// ============================================

int strategy_init(strategy_context_t* ctx, strategy_type_t type, uint32_t chunk_count) {
    memset(ctx, 0, sizeof(strategy_context_t));
    
    ctx->type = type;
    ctx->total_chunks = chunk_count;
    ctx->random_seed = (uint32_t)(time(NULL) ^ getpid());
    
    pthread_mutex_init(&ctx->mutex, NULL);
    
    // Allocate chunk trackers
    ctx->chunks = calloc(chunk_count, sizeof(chunk_tracker_t));
    if (!ctx->chunks) {
        LOG_ERROR("Strategy: Failed to allocate %u chunk trackers", chunk_count);
        return -1;
    }
    
    for (uint32_t i = 0; i < chunk_count; i++) {
        ctx->chunks[i].chunk_index = i;
        ctx->chunks[i].availability = 0;
        ctx->chunks[i].downloaded = false;
        ctx->chunks[i].in_progress = false;
        ctx->chunks[i].retry_count = 0;
    }
    
    ctx->started_at = get_timestamp_ms();
    
    LOG_INFO("Strategy initialized: %s (%u chunks)", 
             strategy_type_string(type), chunk_count);
    return 0;
}

void strategy_cleanup(strategy_context_t* ctx) {
    pthread_mutex_lock(&ctx->mutex);
    
    if (ctx->chunks) {
        free(ctx->chunks);
        ctx->chunks = NULL;
    }
    
    for (int i = 0; i < ctx->peer_count; i++) {
        if (ctx->peers[i].chunk_bitmap) {
            free(ctx->peers[i].chunk_bitmap);
            ctx->peers[i].chunk_bitmap = NULL;
        }
    }
    
    pthread_mutex_unlock(&ctx->mutex);
    pthread_mutex_destroy(&ctx->mutex);
    
    LOG_INFO("Strategy cleaned up");
}

// ============================================
// PEER MANAGEMENT
// ============================================

int strategy_add_peer(strategy_context_t* ctx, const char* peer_id,
                      const char* ip, uint16_t port) {
    pthread_mutex_lock(&ctx->mutex);
    
    // Check if peer already exists
    for (int i = 0; i < ctx->peer_count; i++) {
        if (strcmp(ctx->peers[i].peer_id, peer_id) == 0) {
            ctx->peers[i].connected = true;
            strncpy(ctx->peers[i].ip, ip, sizeof(ctx->peers[i].ip) - 1);
            ctx->peers[i].port = port;
            pthread_mutex_unlock(&ctx->mutex);
            return 0;
        }
    }
    
    if (ctx->peer_count >= MAX_GROUP_MEMBERS) {
        LOG_WARN("Strategy: Max peers reached (%d)", MAX_GROUP_MEMBERS);
        pthread_mutex_unlock(&ctx->mutex);
        return -1;
    }
    
    peer_source_t* peer = &ctx->peers[ctx->peer_count];
    memset(peer, 0, sizeof(peer_source_t));
    
    strncpy(peer->peer_id, peer_id, sizeof(peer->peer_id) - 1);
    strncpy(peer->ip, ip, sizeof(peer->ip) - 1);
    peer->port = port;
    peer->socket_fd = -1;
    peer->connected = true;
    peer->active = false;
    peer->bandwidth_bps = 0;
    peer->avg_latency_ms = 0;
    
    // Allocate bitmap (assume peer has everything initially)
    peer->chunk_bitmap = calloc(ctx->total_chunks, sizeof(bool));
    if (peer->chunk_bitmap) {
        for (uint32_t i = 0; i < ctx->total_chunks; i++) {
            peer->chunk_bitmap[i] = true; // Assume all available
        }
        peer->chunk_count = ctx->total_chunks;
        peer->available_chunks = ctx->total_chunks;
    }
    
    ctx->peer_count++;
    
    LOG_INFO("Strategy: Added peer %s (%s:%d) [%d total]",
             peer_id, ip, port, ctx->peer_count);
    
    pthread_mutex_unlock(&ctx->mutex);
    return 0;
}

int strategy_remove_peer(strategy_context_t* ctx, const char* peer_id) {
    pthread_mutex_lock(&ctx->mutex);
    
    for (int i = 0; i < ctx->peer_count; i++) {
        if (strcmp(ctx->peers[i].peer_id, peer_id) == 0) {
            ctx->peers[i].connected = false;
            
            // Unassign any in-progress chunks from this peer
            for (uint32_t c = 0; c < ctx->total_chunks; c++) {
                if (ctx->chunks[c].in_progress &&
                    strcmp(ctx->chunks[c].assigned_peer, peer_id) == 0) {
                    ctx->chunks[c].in_progress = false;
                    memset(ctx->chunks[c].assigned_peer, 0, MAX_ID_LENGTH);
                    ctx->in_progress_chunks--;
                    LOG_DEBUG("Strategy: Unassigned chunk %u from disconnected peer %s",
                              c, peer_id);
                }
            }
            
            LOG_INFO("Strategy: Removed peer %s", peer_id);
            pthread_mutex_unlock(&ctx->mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&ctx->mutex);
    return -1;
}

int strategy_set_peer_bitmap(strategy_context_t* ctx, const char* peer_id,
                             const bool* bitmap, uint32_t count) {
    pthread_mutex_lock(&ctx->mutex);
    
    for (int i = 0; i < ctx->peer_count; i++) {
        if (strcmp(ctx->peers[i].peer_id, peer_id) == 0) {
            uint32_t copy_count = count < ctx->total_chunks ? count : ctx->total_chunks;
            
            if (!ctx->peers[i].chunk_bitmap) {
                ctx->peers[i].chunk_bitmap = calloc(ctx->total_chunks, sizeof(bool));
            }
            if (!ctx->peers[i].chunk_bitmap) {
                pthread_mutex_unlock(&ctx->mutex);
                return -1;
            }
            
            memcpy(ctx->peers[i].chunk_bitmap, bitmap, copy_count * sizeof(bool));
            ctx->peers[i].chunk_count = ctx->total_chunks;
            
            // Count available chunks
            uint32_t avail = 0;
            for (uint32_t c = 0; c < copy_count; c++) {
                if (bitmap[c]) avail++;
            }
            ctx->peers[i].available_chunks = avail;
            
            LOG_DEBUG("Strategy: Updated bitmap for %s (%u/%u chunks available)",
                      peer_id, avail, ctx->total_chunks);
            
            pthread_mutex_unlock(&ctx->mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&ctx->mutex);
    return -1;
}

void strategy_update_peer_metrics(strategy_context_t* ctx, const char* peer_id,
                                   double bandwidth, double latency) {
    pthread_mutex_lock(&ctx->mutex);
    
    for (int i = 0; i < ctx->peer_count; i++) {
        if (strcmp(ctx->peers[i].peer_id, peer_id) == 0) {
            // Exponential moving average
            if (ctx->peers[i].bandwidth_bps == 0) {
                ctx->peers[i].bandwidth_bps = bandwidth;
                ctx->peers[i].avg_latency_ms = latency;
            } else {
                ctx->peers[i].bandwidth_bps = 
                    0.7 * ctx->peers[i].bandwidth_bps + 0.3 * bandwidth;
                ctx->peers[i].avg_latency_ms = 
                    0.7 * ctx->peers[i].avg_latency_ms + 0.3 * latency;
            }
            ctx->peers[i].chunks_served++;
            ctx->peers[i].last_activity = get_timestamp_ms();
            break;
        }
    }
    
    pthread_mutex_unlock(&ctx->mutex);
}

void strategy_record_peer_failure(strategy_context_t* ctx, const char* peer_id) {
    pthread_mutex_lock(&ctx->mutex);
    
    for (int i = 0; i < ctx->peer_count; i++) {
        if (strcmp(ctx->peers[i].peer_id, peer_id) == 0) {
            ctx->peers[i].failures++;
            LOG_DEBUG("Strategy: Peer %s failure count: %u",
                      peer_id, ctx->peers[i].failures);
            break;
        }
    }
    
    pthread_mutex_unlock(&ctx->mutex);
}

// ============================================
// CHUNK SELECTION (dispatch to strategy)
// ============================================

int32_t strategy_select_next_chunk(strategy_context_t* ctx, const char* peer_id) {
    pthread_mutex_lock(&ctx->mutex);
    
    int32_t result = -1;
    
    switch (ctx->type) {
        case STRATEGY_SEQUENTIAL:
            result = sequential_select_for_peer(ctx, peer_id);
            break;
        case STRATEGY_RANDOM:
            result = random_select(ctx, peer_id);
            break;
        case STRATEGY_RAREST_FIRST:
            result = rarest_first_select(ctx, peer_id);
            break;
    }
    
    pthread_mutex_unlock(&ctx->mutex);
    return result;
}

// ============================================
// CHUNK STATUS
// ============================================

void strategy_mark_downloaded(strategy_context_t* ctx, uint32_t chunk_index) {
    pthread_mutex_lock(&ctx->mutex);
    
    if (chunk_index < ctx->total_chunks && !ctx->chunks[chunk_index].downloaded) {
        ctx->chunks[chunk_index].downloaded = true;
        ctx->chunks[chunk_index].in_progress = false;
        ctx->completed_chunks++;
        
        if (ctx->chunks[chunk_index].in_progress) {
            ctx->in_progress_chunks--;
        }
        
        ctx->bytes_downloaded += CHUNK_SIZE;
        
        // Update overall rate
        uint64_t elapsed = get_timestamp_ms() - ctx->started_at;
        if (elapsed > 0) {
            ctx->overall_rate_bps = 
                (double)ctx->bytes_downloaded / ((double)elapsed / 1000.0);
        }
    }
    
    pthread_mutex_unlock(&ctx->mutex);
}

void strategy_mark_in_progress(strategy_context_t* ctx, uint32_t chunk_index,
                                const char* peer_id) {
    pthread_mutex_lock(&ctx->mutex);
    
    if (chunk_index < ctx->total_chunks) {
        ctx->chunks[chunk_index].in_progress = true;
        ctx->chunks[chunk_index].request_time = get_timestamp_ms();
        strncpy(ctx->chunks[chunk_index].assigned_peer, peer_id, MAX_ID_LENGTH - 1);
        ctx->in_progress_chunks++;
    }
    
    pthread_mutex_unlock(&ctx->mutex);
}

void strategy_mark_failed(strategy_context_t* ctx, uint32_t chunk_index) {
    pthread_mutex_lock(&ctx->mutex);
    
    if (chunk_index < ctx->total_chunks) {
        ctx->chunks[chunk_index].in_progress = false;
        ctx->chunks[chunk_index].retry_count++;
        memset(ctx->chunks[chunk_index].assigned_peer, 0, MAX_ID_LENGTH);
        
        if (ctx->in_progress_chunks > 0) {
            ctx->in_progress_chunks--;
        }
        
        LOG_DEBUG("Strategy: Chunk %u failed (retry %u)",
                  chunk_index, ctx->chunks[chunk_index].retry_count);
    }
    
    pthread_mutex_unlock(&ctx->mutex);
}

// ============================================
// QUERY
// ============================================

bool strategy_is_complete(const strategy_context_t* ctx) {
    return ctx->completed_chunks >= ctx->total_chunks;
}

float strategy_get_progress(const strategy_context_t* ctx) {
    if (ctx->total_chunks == 0) return 1.0f;
    return (float)ctx->completed_chunks / (float)ctx->total_chunks;
}

void strategy_get_stats(const strategy_context_t* ctx, uint32_t* completed,
                        uint32_t* in_progress, uint32_t* remaining) {
    if (completed) *completed = ctx->completed_chunks;
    if (in_progress) *in_progress = ctx->in_progress_chunks;
    if (remaining) {
        *remaining = ctx->total_chunks - ctx->completed_chunks - ctx->in_progress_chunks;
    }
}