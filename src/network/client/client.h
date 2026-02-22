#ifndef P2P_CLIENT_H
#define P2P_CLIENT_H

#include "client_types.h"
#include "client_messaging.h"
#include "client_groups.h"
#include "client_files.h"
#include "client_nat.h"

/*  ============================================
    CLIENT TOP-LEVEL API

    Note: Lifecycle only. All operations are in sub-headers:
    - client_messaging.h → send_message, send_ping, callbacks
    - client_groups.h    → create/join/leave/vote/invite
    - client_files.h     → announce_file, request_file_list
    - client_nat.h       → nat_discover, nat_punch, connect_to_peer
    ============================================ */

int  client_init(p2p_client_t* client, const char* relay_host, uint16_t relay_port);
int  client_connect(p2p_client_t* client);
void client_disconnect(p2p_client_t* client);
void client_cleanup(p2p_client_t* client);
bool client_is_connected(p2p_client_t* client);

#endif // P2P_CLIENT_H