#ifndef P2P_RELAY_HANDLERS_BASIC_H
#define P2P_RELAY_HANDLERS_BASIC_H

#include "relay_types.h"

int relay_handle_ping(relay_server_t* server, int client_index, message_t* msg);
int relay_handle_connect(relay_server_t* server, int client_index, message_t* msg);
int relay_handle_disconnect(relay_server_t* server, int client_index, message_t* msg);

#endif // P2P_RELAY_HANDLERS_BASIC_H