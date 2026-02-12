#include "strategy.h"
#include "../../common/logging.h"

#include <stdlib.h>
#include <time.h>

// ============================================
// RANDOM CHUNK SELECTION
// ============================================
// Picks a random chunk from the set of missing chunks.
//
// Pros: Good distribution across peers, reduces contention,
//       makes each peer's contribution unique
// Cons: Doesn't prioritize rare chunks, not optimal for streaming

// Simple xorshift32 PRNG (deterministic, fast, no global state)
static uint32_t xorshift32(uint32_t* state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

int32_t random_select(strategy_context_t* ctx, const char* peer_id) {
    // Find peer
    peer_source_t* peer = NULL;
    for (int i = 0; i < ctx->peer_count; i++) {
        if (strcmp(ctx->peers[i].peer_id, peer_id) == 0) {
            peer = &ctx->peers[i];
            break;
        }
    }

    // Build array of candidate chunk indices
    uint32_t* candidates = NULL;
    uint32_t candidate_count = 0;
    uint32_t candidate_cap = 256;

    candidates = malloc(candidate_cap * sizeof(uint32_t));
    if (!candidates) return -1;

    for (uint32_t i = 0; i < ctx->total_chunks; i++) {
        if (ctx->chunks[i].downloaded || ctx->chunks[i].in_progress) {
            continue;
        }
        if (peer && peer->chunk_bitmap && !peer->chunk_bitmap[i]) {
            continue;
        }
        // Grow array if needed
        if (candidate_count >= candidate_cap) {
            candidate_cap *= 2;
            uint32_t* tmp = realloc(candidates, candidate_cap * sizeof(uint32_t));
            if (!tmp) {
                free(candidates);
                return -1;
            }
            candidates = tmp;
        }
        candidates[candidate_count++] = i;
    }

    if (candidate_count == 0) {
        free(candidates);
        return -1;
    }

    // Pick random candidate
    uint32_t pick = xorshift32(&ctx->random_seed) % candidate_count;
    int32_t result = (int32_t)candidates[pick];

    free(candidates);
    return result;
}