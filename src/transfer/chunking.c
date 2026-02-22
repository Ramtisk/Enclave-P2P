#include "chunking.h"
#include "../common/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

// ============================================
// SHA-256 is now in sha256.c
// Transfer context functions are now in transfer_context.c
// ============================================

// ============================================
// HASHING HELPERS (wrappers — sha256_hash is in sha256.c)
// ============================================

int file_hash_calculate(const char* filepath, uint8_t* hash_out) {
    FILE* f = fopen(filepath, "rb");
    if (!f) {
        LOG_ERROR("Cannot open file for hashing: %s", filepath);
        return -1;
    }    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t* buf = malloc(size);
    if (!buf) {
        fclose(f);
        return -1;
    }
    fread(buf, 1, size, f);
    fclose(f);

    sha256_hash(buf, size, hash_out);
    free(buf);
    return 0;
}

void hash_to_hex(const uint8_t* hash, char* hex_out, size_t hex_len) {
    if (hex_len < FILE_HASH_SIZE * 2 + 1) return;

    for (int i = 0; i < FILE_HASH_SIZE; i++) {
        snprintf(hex_out + i * 2, 3, "%02x", hash[i]);
    }
    hex_out[FILE_HASH_SIZE * 2] = '\0';
}

bool hash_compare(const uint8_t* hash1, const uint8_t* hash2) {
    return memcmp(hash1, hash2, FILE_HASH_SIZE) == 0;
}

// ============================================
// CHUNKING FUNCTIONS
// ============================================

uint32_t calculate_chunk_count(uint64_t file_size) {
    if (file_size == 0) return 0;
    return (uint32_t)((file_size + CHUNK_SIZE - 1) / CHUNK_SIZE);
}

file_metadata_t* file_metadata_create(const char* filepath) {
    struct stat st;
    if (stat(filepath, &st) != 0) {
        LOG_ERROR("Cannot stat file: %s", filepath);
        return NULL;
    }

    file_metadata_t* meta = calloc(1, sizeof(file_metadata_t));
    if (!meta) {
        LOG_ERROR("Memory allocation failed");
        return NULL;
    }

    strncpy(meta->file_path, filepath, sizeof(meta->file_path) - 1);

    // Extract filename from path
    const char* name = strrchr(filepath, '/');
    name = name ? name + 1 : filepath;
    strncpy(meta->filename, name, MAX_FILENAME - 1);

    meta->file_size = st.st_size;
    meta->chunk_count = calculate_chunk_count(st.st_size);

    LOG_INFO("Creating metadata for: %s (%lu bytes, %u chunks)",
             meta->filename, meta->file_size, meta->chunk_count);

    // Calculate file hash
    if (file_hash_calculate(filepath, meta->file_hash) != 0) {
        free(meta);
        return NULL;
    }

    char hex[65];
    hash_to_hex(meta->file_hash, hex, sizeof(hex));
    LOG_INFO("File hash: %s", hex);

    // Allocate and calculate chunk hashes
    meta->chunk_hashes = calloc(meta->chunk_count, FILE_HASH_SIZE);
    if (!meta->chunk_hashes) {
        free(meta);
        return NULL;
    }

    FILE* f = fopen(filepath, "rb");
    if (!f) {
        free(meta->chunk_hashes);
        free(meta);
        return NULL;
    }

    uint8_t buffer[CHUNK_SIZE];
    for (uint32_t i = 0; i < meta->chunk_count; i++) {
        size_t bytes_read = fread(buffer, 1, CHUNK_SIZE, f);
        sha256_hash(buffer, bytes_read, meta->chunk_hashes[i]);
    }

    fclose(f);
    meta->is_complete = true;

    LOG_INFO("Metadata created successfully");
    return meta;
}

void file_metadata_free(file_metadata_t* meta) {
    if (!meta) return;
    if (meta->chunk_hashes) {
        free(meta->chunk_hashes);
    }
    free(meta);
}

int chunk_read(const char* filepath, uint32_t chunk_index, chunk_t* chunk_out) {
    FILE* f = fopen(filepath, "rb");
    if (!f) {
        LOG_ERROR("Cannot open file: %s", filepath);
        return -1;
    }

    memset(chunk_out, 0, sizeof(chunk_t));
    chunk_out->index = chunk_index;

    off_t offset = (off_t)chunk_index * CHUNK_SIZE;
    if (fseek(f, offset, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    chunk_out->size = fread(chunk_out->data, 1, CHUNK_SIZE, f);
    fclose(f);

    if (chunk_out->size == 0) {
        return -1;
    }

    sha256_hash(chunk_out->data, chunk_out->size, chunk_out->hash);
    chunk_out->verified = true;

    return 0;
}

int chunk_write(const char* filepath, uint32_t chunk_index, const chunk_t* chunk) {
    int fd = open(filepath, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) {
        LOG_ERROR("Cannot open file for writing: %s", filepath);
        return -1;
    }

    off_t offset = (off_t)chunk_index * CHUNK_SIZE;
    if (lseek(fd, offset, SEEK_SET) != offset) {
        close(fd);
        return -1;
    }

    ssize_t written = write(fd, chunk->data, chunk->size);
    close(fd);

    if (written != (ssize_t)chunk->size) {
        LOG_ERROR("Write failed: expected %u, wrote %zd", chunk->size, written);
        return -1;
    }

    LOG_DEBUG("Wrote chunk %u (%u bytes) to %s", chunk_index, chunk->size, filepath);
    return 0;
}

bool chunk_verify(const chunk_t* chunk, const uint8_t* expected_hash) {
    uint8_t calculated[FILE_HASH_SIZE];
    sha256_hash(chunk->data, chunk->size, calculated);
    return hash_compare(calculated, expected_hash);
}