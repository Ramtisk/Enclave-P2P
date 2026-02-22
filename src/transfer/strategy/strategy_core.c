#include "strategy.h"
#include "../../common/logging.h"

// ============================================
// SEQUENTIAL CHUNK SELECTION
// ============================================
// Simply picks the lowest-index chunk that hasn't been
// downloaded or isn't currently in progress.
//
// Pros: Simple, predictable, good for streaming playback
// Cons: No load balancing, doesn't prioritize rare chunks

int32_t sequential_select(strategy_context_t* ctx, const char* peer_id) {
    (void)peer_id; // Sequential doesn't care which peer

    for (uint32_t i = 0; i < ctx->total_chunks; i++) {
        if (!ctx->chunks[i].downloaded && !ctx->chunks[i].in_progress) {
            return (int32_t)i;
        }
    }

    return -1; // All chunks downloaded or in progress
}

// Peer-aware variant: pick lowest chunk that the given peer actually has
int32_t sequential_select_for_peer(strategy_context_t* ctx, const char* peer_id) {
    // Find peer
    peer_source_t* peer = NULL;
    for (int i = 0; i < ctx->peer_count; i++) {
        if (strcmp(ctx->peers[i].peer_id, peer_id) == 0) {
            peer = &ctx->peers[i];
            break;
        }
    }

    for (uint32_t i = 0; i < ctx->total_chunks; i++) {
        if (ctx->chunks[i].downloaded || ctx->chunks[i].in_progress) {
            continue;
        }
        // If we have peer info, check if peer has this chunk
        if (peer && peer->chunk_bitmap && !peer->chunk_bitmap[i]) {
            continue;
        }
        return (int32_t)i;
    }

    return -1;
}