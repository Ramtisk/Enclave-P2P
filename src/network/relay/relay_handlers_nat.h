#ifndef P2P_RELAY_HANDLERS_NAT_H
#define P2P_RELAY_HANDLERS_NAT_H

#include "relay_types.h"

int relay_handle_nat_discover(relay_server_t* server, int client_index, message_t* msg);
int relay_handle_nat_punch_req(relay_server_t* server, int client_index, message_t* msg);
int relay_handle_nat_punch_result(relay_server_t* server, int client_index, message_t* msg);
int relay_handle_nat_relay_data(relay_server_t* server, int client_index, message_t* msg);

#endif // P2P_RELAY_HANDLERS_NAT_H