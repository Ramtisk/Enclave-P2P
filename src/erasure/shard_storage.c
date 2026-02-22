#define _POSIX_C_SOURCE 200809L
#include "shard_storage.h"
#include "shard_helpers.h"
#include "../common/logging.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

/*  Function: shard_file_path (static)
    Description:
    Constructs the local filesystem path for a shard file.

    Steps:
    1. Converts the first 8 bytes of file_hash to hex.
    2. Formats as "<shard_dir>/<hash_hex>/shard_<index>.bin".
*/
static void shard_file_path(const shard_manager_t* mgr, const char* file_hash,
                             int shard_index, char* path, size_t path_len) {
    char hash_hex[17];
    shard_bytes_to_hex((const uint8_t*)file_hash, 8, hash_hex, sizeof(hash_hex));
    snprintf(path, path_len, "%s/%s/shard_%03d.bin",
             mgr->shard_dir, hash_hex, shard_index);
}

/*  Function: shard_store_local
    Description:
    Writes shard data to a local file on disk.

    Parameters:
    - mgr: Pointer to the shard_manager_t.
    - file_hash: File hash.
    - shard_index: Shard index.
    - data: Shard data buffer.
    - len: Length of shard data.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Constructs the file path.
    2. Opens the file for writing.
    3. Writes the data and closes.
    4. Updates manager statistics.
*/
int shard_store_local(shard_manager_t* mgr, const char* file_hash,
                      int shard_index, const uint8_t* data, size_t len) {
    if (!mgr || !file_hash || !data) return -1;

    char path[700];
    shard_file_path(mgr, file_hash, shard_index, path, sizeof(path));

    FILE* f = fopen(path, "wb");
    if (!f) {
        LOG_ERROR("shard: Cannot write %s: %s", path, strerror(errno));
        return -1;
    }

    size_t written = fwrite(data, 1, len, f);
    fclose(f);

    if (written != len) {
        LOG_ERROR("shard: Partial write to %s", path);
        return -1;
    }

    mgr->total_shards_stored++;
    mgr->total_bytes_stored += len;

    LOG_TRACE("shard: Stored shard %d (%zu bytes) → %s", shard_index, len, path);
    return 0;
}

/*  Function: shard_load_local
    Description:
    Reads shard data from a local file on disk.

    Parameters:
    - mgr: Pointer to the shard_manager_t.
    - file_hash: File hash.
    - shard_index: Shard index.
    - data: Output buffer.
    - max_len: Maximum buffer size.
    - actual_len: Output pointer for bytes read.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Constructs the file path and opens for reading.
    2. Determines file size and validates against max_len.
    3. Reads the data and closes.
*/
int shard_load_local(shard_manager_t* mgr, const char* file_hash,
                     int shard_index, uint8_t* data, size_t max_len,
                     size_t* actual_len) {
    if (!mgr || !file_hash || !data) return -1;

    char path[700];
    shard_file_path(mgr, file_hash, shard_index, path, sizeof(path));

    FILE* f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size < 0 || (size_t)file_size > max_len) {
        fclose(f);
        return -1;
    }

    size_t rd = fread(data, 1, (size_t)file_size, f);
    fclose(f);

    if (actual_len) *actual_len = rd;
    return 0;
}

/*  Function: shard_exists_local
    Description:
    Checks whether a shard file exists on the local filesystem.

    Parameters:
    - mgr: Pointer to the shard_manager_t.
    - file_hash: File hash.
    - shard_index: Shard index.

    Returns:
    - true if the file exists and is a regular file, false otherwise.
*/
bool shard_exists_local(const shard_manager_t* mgr, const char* file_hash,
                        int shard_index) {
    if (!mgr || !file_hash) return false;

    char path[700];
    shard_file_path(mgr, file_hash, shard_index, path, sizeof(path));

    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
}