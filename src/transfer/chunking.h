#ifndef P2P_CHUNKING_H
#define P2P_CHUNKING_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "../common/config.h"
#include "../common/protocol.h"

// ============================================
// CHUNK STRUCTURE
// ============================================
typedef struct
{
    uint32_t index;
    uint32_t size;
    uint8_t hash[FILE_HASH_SIZE]; // SHA-256 of chunk
    uint8_t data[CHUNK_SIZE];
    bool verified;
} chunk_t;

// ============================================
// FILE METADATA
// ============================================
typedef struct
{
    char file_path[512];
    char filename[MAX_FILENAME];
    uint8_t file_hash[FILE_HASH_SIZE]; // SHA-256 of entire file
    uint64_t file_size;
    uint32_t chunk_count;
    uint8_t (*chunk_hashes)[FILE_HASH_SIZE]; // Array of chunk hashes
    bool is_complete;
} file_metadata_t;

// ============================================
// TRANSFER STATE
// ============================================
typedef enum
{
    TRANSFER_IDLE = 0,
    TRANSFER_ANNOUNCING,
    TRANSFER_WAITING_PEER,
    TRANSFER_CONNECTING,
    TRANSFER_IN_PROGRESS,
    TRANSFER_PAUSED,
    TRANSFER_COMPLETE,
    TRANSFER_FAILED
} transfer_state_t;

typedef struct
{
    file_metadata_t metadata;
    transfer_state_t state;

    // Progress tracking
    uint32_t chunks_completed;
    bool *chunk_bitmap; // Which chunks we have
    uint64_t bytes_transferred;
    uint64_t started_at;
    uint64_t last_activity;

    // Peer info
    char peer_id[MAX_ID_LENGTH];
    char peer_ip[46];
    uint16_t peer_port;
    int peer_socket;

    // Stats
    uint32_t retries;
    double transfer_rate; // bytes/sec
} transfer_context_t;

// ============================================
// FUNCTIONS - Hashing
// ============================================

// Calculate SHA-256 hash
void sha256_hash(const uint8_t *data, size_t len, uint8_t *hash_out);

// Hash entire file
int file_hash_calculate(const char *filepath, uint8_t *hash_out);

// Hash to hex string
void hash_to_hex(const uint8_t *hash, char *hex_out, size_t hex_len);

// Compare two hashes
bool hash_compare(const uint8_t *hash1, const uint8_t *hash2);

// ============================================
// FUNCTIONS - Chunking
// ============================================

// Create metadata for a file (calculates all hashes)
file_metadata_t *file_metadata_create(const char *filepath);

// Free metadata
void file_metadata_free(file_metadata_t *meta);

// Get chunk count for file size
uint32_t calculate_chunk_count(uint64_t file_size);

// Read a specific chunk from file
int chunk_read(const char *filepath, uint32_t chunk_index, chunk_t *chunk_out);

// Write a chunk to file
int chunk_write(const char *filepath, uint32_t chunk_index, const chunk_t *chunk);

// Verify chunk hash
bool chunk_verify(const chunk_t *chunk, const uint8_t *expected_hash);

// ============================================
// FUNCTIONS - Transfer Context
// ============================================

// Create transfer context for sending
transfer_context_t *transfer_context_create_send(const char *filepath);

// Create transfer context for receiving
transfer_context_t *transfer_context_create_recv(const file_metadata_t *meta,
                                                 const char *save_path);

// Free transfer context
void transfer_context_free(transfer_context_t *ctx);

// Update transfer progress
void transfer_update_progress(transfer_context_t *ctx, uint32_t chunk_index);

// Check if transfer is complete
bool transfer_is_complete(const transfer_context_t *ctx);

// Get next missing chunk index (-1 if none)
int32_t transfer_get_next_missing_chunk(const transfer_context_t *ctx);

// Verify final file integrity
bool transfer_verify_complete(transfer_context_t *ctx);

#endif // P2P_CHUNKING_H