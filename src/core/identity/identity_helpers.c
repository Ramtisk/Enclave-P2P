#define _POSIX_C_SOURCE 200809L
#include "identity_helpers.h"
#include <stdio.h>
#include <time.h>

/*  Function: identity_get_timestamp_ms
    Description:
    Returns the current timestamp in milliseconds since the Unix epoch.

    Steps:
    1. Calls clock_gettime with CLOCK_REALTIME.
    2. Converts seconds and nanoseconds to milliseconds.
    3. Returns the result as a 64-bit integer.
*/
uint64_t identity_get_timestamp_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/*  Function: identity_bytes_to_hex
    Description:
    Converts a byte array to a null-terminated hex string.

    Parameters:
    - bytes: Input byte array.
    - len: Number of bytes to convert.
    - hex: Output buffer for the hex string.
    - hex_len: Size of the output buffer.

    Steps:
    1. Calculates the maximum number of bytes that fit in the output buffer.
    2. Converts each byte to two hex characters.
    3. Null-terminates the output string.
*/
void identity_bytes_to_hex(const uint8_t *bytes, size_t len,
                           char *hex, size_t hex_len)
{
    size_t max = (hex_len - 1) / 2;
    if (max > len)
        max = len;
    for (size_t i = 0; i < max; i++)
    {
        snprintf(hex + i * 2, 3, "%02x", bytes[i]);
    }
    hex[max * 2] = '\0';
}