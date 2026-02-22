#define _POSIX_C_SOURCE 200809L
#include "shard_helpers.h"

#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

/*  Function: shard_get_timestamp_ms
    Description:
    Returns the current timestamp in milliseconds since the Unix epoch.

    Steps:
    1. Calls clock_gettime with CLOCK_REALTIME.
    2. Converts to milliseconds and returns.
*/
uint64_t shard_get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/*  Function: shard_bytes_to_hex
    Description:
    Converts a byte array to a null-terminated hex string.

    Parameters:
    - bytes: Input byte array.
    - len: Number of bytes.
    - hex: Output hex string buffer.
    - hex_len: Size of the hex buffer.
*/
void shard_bytes_to_hex(const uint8_t* bytes, size_t len,
                        char* hex, size_t hex_len) {
    size_t max = (hex_len - 1) / 2;
    if (max > len) max = len;
    for (size_t i = 0; i < max; i++) {
        snprintf(hex + i * 2, 3, "%02x", bytes[i]);
    }
    hex[max * 2] = '\0';
}

/*  Function: shard_ensure_directory
    Description:
    Creates a directory if it doesn't exist.

    Parameters:
    - path: Directory path.

    Returns:
    - 0 on success, -1 if path exists but is not a directory.
*/
int shard_ensure_directory(const char* path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        return S_ISDIR(st.st_mode) ? 0 : -1;
    }
    return mkdir(path, 0700);
}