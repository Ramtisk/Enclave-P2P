#include "strategy.h"
#include "../../common/logging.h"

#include <stdlib.h>
#include <string.h>

// ============================================
// RAREST-FIRST CHUNK SELECTION
// ============================================
// Picks the chunk with the lowest availability count
// (fewest peers have it). Ties broken by lowest index.
//
// This is the core BitTorrent strategy:
// - Ensures rare chunks get downloaded first
// - Maximizes the chance that every chunk exists
//   somewhere in the swarm
// - Prevents the "last piece" problem
//
// Availability is recalculated from peer bitmaps.

// Recalculate availability counts from peer bitmaps
static void recalculate_availability(strategy_context_t* ctx) {
    for (uint32_t i = 0; i < ctx->total_chunks; i++) {
        if (ctx->chunks[i].downloaded) {
            continue; // Don't bother counting completed chunks
        }
        uint32_t count = 0;
        for (int p = 0; p < ctx->peer_count; p++) {
            if (!ctx->peers[p].connected) continue;
            if (ctx->peers[p].chunk_bitmap &&
                ctx->peers[p].chunk_bitmap[i]) {
                count++;
            }
        }
        ctx->chunks[i].availability = count;
    }
}

int32_t rarest_first_select(strategy_context_t* ctx, const char* peer_id) {
    // Find peer
    peer_source_t* peer = NULL;
    for (int i = 0; i < ctx->peer_count; i++) {
        if (strcmp(ctx->peers[i].peer_id, peer_id) == 0) {
            peer = &ctx->peers[i];
            break;
        }
    }

    // Recalculate availability
    recalculate_availability(ctx);

    int32_t best_chunk = -1;
    uint32_t best_availability = UINT32_MAX;

    for (uint32_t i = 0; i < ctx->total_chunks; i++) {
        // Skip completed or in-progress
        if (ctx->chunks[i].downloaded || ctx->chunks[i].in_progress) {
            continue;
        }

        // Skip chunks this peer doesn't have
        if (peer && peer->chunk_bitmap && !peer->chunk_bitmap[i]) {
            continue;
        }

        // Skip unavailable chunks (no peer has them)
        if (ctx->chunks[i].availability == 0) {
            continue;
        }

        // Pick rarest (lowest availability), break ties by index
        if (ctx->chunks[i].availability < best_availability) {
            best_availability = ctx->chunks[i].availability;
            best_chunk = (int32_t)i;
        }
    }

    if (best_chunk >= 0) {
        LOG_TRACE("Rarest-first: selected chunk %d (availability: %u)",
                  best_chunk, best_availability);
    }

    return best_chunk;
}