#include "file_manager.h"
#include "../common/logging.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int file_manager_init(file_manager_t* mgr, const char* shared_dir, const char* download_dir) {
    memset(mgr, 0, sizeof(file_manager_t));
    pthread_mutex_init(&mgr->mutex, NULL);
    strncpy(mgr->shared_dir, shared_dir, sizeof(mgr->shared_dir) - 1);
    strncpy(mgr->download_dir, download_dir, sizeof(mgr->download_dir) - 1);
    mkdir(shared_dir, 0755);
    mkdir(download_dir, 0755);
    return 0;
}

void file_manager_cleanup(file_manager_t* mgr) {
    pthread_mutex_lock(&mgr->mutex);
    for (int i = 0; i < mgr->file_count; i++)
        if (mgr->files[i].metadata.chunk_hashes)
            free(mgr->files[i].metadata.chunk_hashes);
    mgr->file_count = 0;
    pthread_mutex_unlock(&mgr->mutex);
    pthread_mutex_destroy(&mgr->mutex);
}

int file_manager_share_file(file_manager_t* mgr, const char* filepath, const char* owner_id) {
    pthread_mutex_lock(&mgr->mutex);
    if (mgr->file_count >= MAX_SHARED_FILES) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    file_metadata_t* meta = file_metadata_create(filepath);
    if (!meta) { pthread_mutex_unlock(&mgr->mutex); return -1; }

    for (int i = 0; i < mgr->file_count; i++) {
        if (hash_compare(mgr->files[i].metadata.file_hash, meta->file_hash)) {
            file_metadata_free(meta);
            pthread_mutex_unlock(&mgr->mutex);
            return -2;
        }
    }

    shared_file_t* entry = &mgr->files[mgr->file_count];
    memcpy(&entry->metadata, meta, sizeof(file_metadata_t));
    entry->metadata.chunk_hashes = meta->chunk_hashes;
    meta->chunk_hashes = NULL;
    strncpy(entry->owner_id, owner_id, MAX_ID_LENGTH - 1);
    entry->announced_at = get_timestamp_ms();
    entry->available = true;
    mgr->file_count++;
    free(meta);
    pthread_mutex_unlock(&mgr->mutex);
    return 0;
}

int file_manager_register_file(file_manager_t* mgr, const payload_file_announce_t* announce,
                               const char* owner_ip, uint16_t owner_port) {
    pthread_mutex_lock(&mgr->mutex);
    for (int i = 0; i < mgr->file_count; i++) {
        if (memcmp(mgr->files[i].metadata.file_hash, announce->file_hash, FILE_HASH_SIZE) == 0) {
            mgr->files[i].available = true;
            strncpy(mgr->files[i].owner_ip, owner_ip, sizeof(mgr->files[i].owner_ip) - 1);
            mgr->files[i].owner_port = owner_port;
            pthread_mutex_unlock(&mgr->mutex);
            return 0;
        }
    }
    if (mgr->file_count >= MAX_SHARED_FILES) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    shared_file_t* entry = &mgr->files[mgr->file_count];
    memset(entry, 0, sizeof(shared_file_t));
    memcpy(entry->metadata.file_hash, announce->file_hash, FILE_HASH_SIZE);
    strncpy(entry->metadata.filename, announce->filename, MAX_FILENAME - 1);
    entry->metadata.file_size = announce->file_size;
    entry->metadata.chunk_count = announce->chunk_count;
    entry->metadata.is_complete = false;
    strncpy(entry->owner_ip, owner_ip, sizeof(entry->owner_ip) - 1);
    entry->owner_port = owner_port;
    entry->available = true;
    mgr->file_count++;
    pthread_mutex_unlock(&mgr->mutex);
    return 0;
}

shared_file_t* file_manager_find_by_hash(file_manager_t* mgr, const uint8_t* file_hash) {
    for (int i = 0; i < mgr->file_count; i++)
        if (hash_compare(mgr->files[i].metadata.file_hash, file_hash))
            return &mgr->files[i];
    return NULL;
}

int file_manager_get_file_list(file_manager_t* mgr, payload_file_list_response_t* response) {
    pthread_mutex_lock(&mgr->mutex);
    response->file_count = 0;
    for (int i = 0; i < mgr->file_count && response->file_count < 32; i++) {
        if (mgr->files[i].available) {
            memcpy(response->files[response->file_count].file_hash,
                   mgr->files[i].metadata.file_hash, FILE_HASH_SIZE);
            strncpy(response->files[response->file_count].filename,
                    mgr->files[i].metadata.filename, MAX_FILENAME - 1);
            response->files[response->file_count].file_size = mgr->files[i].metadata.file_size;
            strncpy(response->files[response->file_count].owner_id,
                    mgr->files[i].owner_id, MAX_ID_LENGTH - 1);
            response->file_count++;
        }
    }
    pthread_mutex_unlock(&mgr->mutex);
    return response->file_count;
}

int file_manager_remove_file(file_manager_t* mgr, const uint8_t* file_hash) {
    pthread_mutex_lock(&mgr->mutex);
    for (int i = 0; i < mgr->file_count; i++) {
        if (hash_compare(mgr->files[i].metadata.file_hash, file_hash)) {
            if (mgr->files[i].metadata.chunk_hashes)
                free(mgr->files[i].metadata.chunk_hashes);
            for (int j = i; j < mgr->file_count - 1; j++)
                mgr->files[j] = mgr->files[j + 1];
            mgr->file_count--;
            pthread_mutex_unlock(&mgr->mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&mgr->mutex);
    return -1;
}