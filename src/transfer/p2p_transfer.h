#ifndef P2P_TRANSFER_H
#define P2P_TRANSFER_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "chunking.h"
#include "../common/config.h"
#include "../common/protocol.h"

// ============================================
// SHARED FILE ENTRY
// ============================================
typedef struct {
    file_metadata_t metadata;
    char owner_id[MAX_ID_LENGTH];
    char owner_ip[46];
    uint16_t owner_port;
    uint64_t announced_at;
    bool available;
} shared_file_t;

// ============================================
// FILE MANAGER
// ============================================
typedef struct {
    shared_file_t files[MAX_SHARED_FILES];
    int file_count;
    pthread_mutex_t mutex;
    
    // Local sharing
    char shared_dir[512];
    char download_dir[512];
} file_manager_t;

// ============================================
// P2P SERVER (for receiving connections)
// ============================================
typedef struct {
    int server_fd;
    uint16_t port;
    bool running;
    pthread_t accept_thread;
    
    // Active transfers (as sender)
    transfer_context_t* send_transfers[MAX_ACTIVE_TRANSFERS];
    int send_count;
    pthread_mutex_t send_mutex;
} p2p_server_t;

// ============================================
// CALLBACK TYPES
// ============================================
typedef void (*transfer_progress_cb)(const transfer_context_t* ctx, void* user_data);
typedef void (*transfer_complete_cb)(const transfer_context_t* ctx, bool success, void* user_data);

// ============================================
// FILE MANAGER FUNCTIONS
// ============================================

// Initialize file manager
int file_manager_init(file_manager_t* mgr, const char* shared_dir, const char* download_dir);

// Cleanup
void file_manager_cleanup(file_manager_t* mgr);

// Add local file to share
int file_manager_share_file(file_manager_t* mgr, const char* filepath, 
                            const char* owner_id);

// Register remote file
int file_manager_register_file(file_manager_t* mgr, 
                               const payload_file_announce_t* announce,
                               const char* owner_ip, uint16_t owner_port);

// Find file by hash
shared_file_t* file_manager_find_by_hash(file_manager_t* mgr, 
                                          const uint8_t* file_hash);

// Get list of available files
int file_manager_get_file_list(file_manager_t* mgr, 
                               payload_file_list_response_t* response);

// Remove file
int file_manager_remove_file(file_manager_t* mgr, const uint8_t* file_hash);

// ============================================
// P2P SERVER FUNCTIONS
// ============================================

// Initialize P2P server
int p2p_server_init(p2p_server_t* server, uint16_t port);

// Start accepting connections
int p2p_server_start(p2p_server_t* server, file_manager_t* file_mgr);

// Stop server
void p2p_server_stop(p2p_server_t* server);

// Cleanup
void p2p_server_cleanup(p2p_server_t* server);

// ============================================
// P2P TRANSFER FUNCTIONS
// ============================================

// Download file from peer (blocking)
int p2p_download_file(const char* peer_ip, uint16_t peer_port,
                      const uint8_t* file_hash, const char* save_path,
                      transfer_progress_cb progress_cb,
                      transfer_complete_cb complete_cb,
                      void* user_data);

// Download file asynchronously
transfer_context_t* p2p_download_file_async(const char* peer_ip, uint16_t peer_port,
                                            const uint8_t* file_hash,
                                            const char* save_path);

// Send file to peer (called by server)
int p2p_send_file(int client_socket, file_manager_t* file_mgr,
                  const uint8_t* file_hash);

// Check transfer status
transfer_state_t p2p_get_transfer_state(transfer_context_t* ctx);

// Cancel transfer
void p2p_cancel_transfer(transfer_context_t* ctx);

int p2p_download_file_with_fd(int peer_fd, const uint8_t* file_hash,
                               const char* save_path,
                               void (*progress_cb)(uint32_t chunk, uint32_t total, void* data),
                               void (*complete_cb)(bool success, void* data),
                               void* user_data);

#endif // P2P_TRANSFER_H