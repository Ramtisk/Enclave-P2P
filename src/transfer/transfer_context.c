#include "transfer_context.h"
#include "../common/logging.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

transfer_context_t* transfer_context_create_send(const char* filepath) {
    file_metadata_t* meta = file_metadata_create(filepath);
    if (!meta) return NULL;

    transfer_context_t* ctx = calloc(1, sizeof(transfer_context_t));
    if (!ctx) { file_metadata_free(meta); return NULL; }

    memcpy(&ctx->metadata, meta, sizeof(file_metadata_t));
    ctx->metadata.chunk_hashes = meta->chunk_hashes;
    meta->chunk_hashes = NULL;
    free(meta);

    ctx->state = TRANSFER_IDLE;
    ctx->peer_socket = -1;
    ctx->chunk_bitmap = calloc(ctx->metadata.chunk_count, sizeof(bool));
    if (ctx->chunk_bitmap) {
        for (uint32_t i = 0; i < ctx->metadata.chunk_count; i++)
            ctx->chunk_bitmap[i] = true;
        ctx->chunks_completed = ctx->metadata.chunk_count;
    }
    return ctx;
}

transfer_context_t* transfer_context_create_recv(const file_metadata_t* meta,
                                                  const char* save_path) {
    transfer_context_t* ctx = calloc(1, sizeof(transfer_context_t));
    if (!ctx) return NULL;

    memcpy(&ctx->metadata, meta, sizeof(file_metadata_t));
    strncpy(ctx->metadata.file_path, save_path, sizeof(ctx->metadata.file_path) - 1);

    if (meta->chunk_hashes) {
        ctx->metadata.chunk_hashes = calloc(meta->chunk_count, FILE_HASH_SIZE);
        if (ctx->metadata.chunk_hashes)
            memcpy(ctx->metadata.chunk_hashes, meta->chunk_hashes,
                   meta->chunk_count * FILE_HASH_SIZE);
    }

    ctx->state = TRANSFER_IDLE;
    ctx->peer_socket = -1;
    ctx->chunks_completed = 0;
    ctx->metadata.is_complete = false;
    ctx->chunk_bitmap = calloc(meta->chunk_count, sizeof(bool));
    return ctx;
}

void transfer_context_free(transfer_context_t* ctx) {
    if (!ctx) return;
    if (ctx->chunk_bitmap) free(ctx->chunk_bitmap);
    if (ctx->metadata.chunk_hashes) free(ctx->metadata.chunk_hashes);
    if (ctx->peer_socket > 0) close(ctx->peer_socket);
    free(ctx);
}

void transfer_update_progress(transfer_context_t* ctx, uint32_t chunk_index) {
    if (!ctx || chunk_index >= ctx->metadata.chunk_count) return;
    if (!ctx->chunk_bitmap[chunk_index]) {
        ctx->chunk_bitmap[chunk_index] = true;
        ctx->chunks_completed++;
        ctx->bytes_transferred += (chunk_index == ctx->metadata.chunk_count - 1) ?
            (ctx->metadata.file_size % CHUNK_SIZE) : CHUNK_SIZE;
    }
    ctx->last_activity = get_timestamp_ms();
    uint64_t elapsed = ctx->last_activity - ctx->started_at;
    if (elapsed > 0)
        ctx->transfer_rate = (double)ctx->bytes_transferred / (elapsed / 1000.0);
}

bool transfer_is_complete(const transfer_context_t* ctx) {
    return ctx && ctx->chunks_completed >= ctx->metadata.chunk_count;
}

int32_t transfer_get_next_missing_chunk(const transfer_context_t* ctx) {
    if (!ctx || !ctx->chunk_bitmap) return -1;
    for (uint32_t i = 0; i < ctx->metadata.chunk_count; i++)
        if (!ctx->chunk_bitmap[i]) return (int32_t)i;
    return -1;
}

bool transfer_verify_complete(transfer_context_t* ctx) {
    if (!ctx) return false;
    uint8_t final_hash[FILE_HASH_SIZE];
    if (file_hash_calculate(ctx->metadata.file_path, final_hash) != 0) return false;
    bool match = hash_compare(final_hash, ctx->metadata.file_hash);
    if (match) {
        ctx->metadata.is_complete = true;
        ctx->state = TRANSFER_COMPLETE;
    } else {
        ctx->state = TRANSFER_FAILED;
    }
    return match;
}