#ifndef P2P_SHARD_HELPERS_H
#define P2P_SHARD_HELPERS_H

#include <stdint.h>
#include <stddef.h>

/*  ============================================
    SHARD INTERNAL HELPERS

    Note: Utility functions used across shard sub-modules.
    ============================================ */
uint64_t shard_get_timestamp_ms(void);
void shard_bytes_to_hex(const uint8_t* bytes, size_t len,
                        char* hex, size_t hex_len);
int shard_ensure_directory(const char* path);

#endif