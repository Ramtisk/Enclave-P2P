#ifndef P2P_DOWNLOAD_H
#define P2P_DOWNLOAD_H

#include "transfer_context.h"
#include "../common/protocol.h"

typedef void (*transfer_progress_cb)(const transfer_context_t* ctx, void* user_data);
typedef void (*transfer_complete_cb)(const transfer_context_t* ctx, bool success, void* user_data);

int p2p_download_file(const char* peer_ip, uint16_t peer_port,
                      const uint8_t* file_hash, const char* save_path,
                      transfer_progress_cb progress_cb,
                      transfer_complete_cb complete_cb,
                      void* user_data);

int p2p_download_file_with_fd(int peer_fd, const uint8_t* file_hash,
                               const char* save_path,
                               void (*progress_cb)(uint32_t chunk, uint32_t total, void* data),
                               void (*complete_cb)(bool success, void* data),
                               void* user_data);

transfer_state_t p2p_get_transfer_state(transfer_context_t* ctx);
void p2p_cancel_transfer(transfer_context_t* ctx);

#endif