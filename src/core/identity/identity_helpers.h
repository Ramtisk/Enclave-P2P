#ifndef P2P_IDENTITY_HELPERS_H
#define P2P_IDENTITY_HELPERS_H

#include <stdint.h>
#include <stddef.h>

/*  ============================================
    IDENTITY HELPERS

    Note: Internal utility functions used across identity modules.
    - get_timestamp_ms: Returns current time in milliseconds.
    - bytes_to_hex: Converts a byte array to a hex string.
    ============================================ */
uint64_t identity_get_timestamp_ms(void);
void identity_bytes_to_hex(const uint8_t *bytes, size_t len,
                           char *hex, size_t hex_len);

#endif