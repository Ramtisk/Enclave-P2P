#ifndef P2P_RELAY_DISPATCH_H
#define P2P_RELAY_DISPATCH_H

#include "relay_types.h"

/*  ============================================
    RELAY MESSAGE DISPATCH + SEND HELPERS
    ============================================ */

int relay_process_message(relay_server_t* server, int client_index, message_t* msg);
int relay_send_to_client(relay_server_t* server, int client_index, message_t* msg);
int relay_broadcast(relay_server_t* server, message_t* msg, int exclude_index);

// Client lookup
client_connection_t* relay_find_client_by_id(relay_server_t* server, const char* id);
int relay_find_client_index_by_id(relay_server_t* server, const char* id);

#endif // P2P_RELAY_DISPATCH_H