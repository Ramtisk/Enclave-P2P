#ifndef P2P_CLIENT_FILES_H
#define P2P_CLIENT_FILES_H

#include "client_types.h"
#include "../../transfer/p2p_transfer.h"

/*  ============================================
    CLIENT FILE OPERATIONS API
    ============================================ */

int client_announce_file(p2p_client_t* client, shared_file_t* file);
int client_request_file_list(p2p_client_t* client);

#endif // P2P_CLIENT_FILES_H