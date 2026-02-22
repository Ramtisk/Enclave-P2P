#ifndef P2P_FILE_MANAGER_H
#define P2P_FILE_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "chunking.h"
#include "../common/config.h"
#include "../common/protocol.h"

typedef struct {
    file_metadata_t metadata;
    char owner_id[MAX_ID_LENGTH];
    char owner_ip[46];
    uint16_t owner_port;
    uint64_t announced_at;
    bool available;
} shared_file_t;

typedef struct {
    shared_file_t files[MAX_SHARED_FILES];
    int file_count;
    pthread_mutex_t mutex;
    char shared_dir[512];
    char download_dir[512];
} file_manager_t;

int file_manager_init(file_manager_t* mgr, const char* shared_dir, const char* download_dir);
void file_manager_cleanup(file_manager_t* mgr);
int file_manager_share_file(file_manager_t* mgr, const char* filepath, const char* owner_id);
int file_manager_register_file(file_manager_t* mgr, const payload_file_announce_t* announce,
                               const char* owner_ip, uint16_t owner_port);
shared_file_t* file_manager_find_by_hash(file_manager_t* mgr, const uint8_t* file_hash);
int file_manager_get_file_list(file_manager_t* mgr, payload_file_list_response_t* response);
int file_manager_remove_file(file_manager_t* mgr, const uint8_t* file_hash);

#endif