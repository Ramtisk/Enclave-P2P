#ifndef P2P_RELAY_HANDLERS_FILE_H
#define P2P_RELAY_HANDLERS_FILE_H

#include "relay_types.h"

int relay_handle_file_announce(relay_server_t* server, int client_index, message_t* msg);
int relay_handle_file_list(relay_server_t* server, int client_index, message_t* msg);

#endif // P2P_RELAY_HANDLERS_FILE_H