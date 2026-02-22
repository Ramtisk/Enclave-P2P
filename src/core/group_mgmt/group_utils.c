#define _POSIX_C_SOURCE 200809L
#include "group_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/*  Function: get_timestamp_ms
    Description:
    Returns the current timestamp in milliseconds since the Unix epoch.

    Returns:
    - uint64_t: Current time in milliseconds.

    Steps:
    1. Calls clock_gettime with CLOCK_REALTIME to get the current time.
    2. Converts seconds and nanoseconds to milliseconds.
    3. Returns the result as a 64-bit integer.
*/
uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/*  Function: generate_group_id
    Description:
    Generates a unique group ID based on the group name and current timestamp.

    Parameters:
    - id: Output buffer to store the generated group ID.
    - len: Length of the output buffer.
    - name: Group name used as part of the ID generation.

    Steps:
    1. Gets the current timestamp in milliseconds.
    2. Computes a hash of the group name using the djb2 algorithm.
    3. Mixes the hash with the timestamp for uniqueness.
    4. Formats the result as a string "grp_%08x" and writes it to the output buffer.
*/
void generate_group_id(char* id, size_t len, const char* name) {
    uint64_t ts = get_timestamp_ms();
    uint32_t hash = 5381;
    for (const char* c = name; *c; c++) {
        hash = ((hash << 5) + hash) + (uint8_t)*c;
    }
    hash ^= (uint32_t)(ts & 0xFFFFFFFF);
    snprintf(id, len, "grp_%08x", hash);
}

/*  Function: generate_invite_token
    Description:
    Generates a random alphanumeric invite token for group invitations.

    Parameters:
    - token: Output buffer to store the generated token.
    - len: Length of the output buffer.

    Steps:
    1. Defines a character set of uppercase, lowercase letters, and digits.
    2. Seeds the random number generator with the current timestamp XOR process ID.
    3. Fills the token buffer with random characters from the charset.
    4. Null-terminates the token string.
*/
void generate_invite_token(char* token, size_t len) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    size_t charset_len = sizeof(charset) - 1;
    srand((unsigned int)(get_timestamp_ms() ^ getpid()));
    size_t token_len = len - 1;
    for (size_t i = 0; i < token_len; i++) {
        token[i] = charset[rand() % charset_len];
    }
    token[token_len] = '\0';
}

/*  Function: generate_request_id
    Description:
    Generates a unique request ID for pending join requests.

    Parameters:
    - id: Output buffer to store the generated request ID.
    - len: Length of the output buffer.

    Steps:
    1. Gets the current timestamp in milliseconds.
    2. Generates a random number between 0 and 9999.
    3. Formats the result as a string "req_<timestamp>_<random>" and writes it to the output buffer.
*/
void generate_request_id(char* id, size_t len) {
    snprintf(id, len, "req_%lu_%d", get_timestamp_ms(), rand() % 10000);
}