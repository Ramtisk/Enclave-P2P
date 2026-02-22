#ifndef P2P_RELAY_HANDLERS_GROUP_H
#define P2P_RELAY_HANDLERS_GROUP_H

#include "relay_types.h"

int relay_handle_group_create(relay_server_t* server, int client_index, message_t* msg);
int relay_handle_group_join(relay_server_t* server, int client_index, message_t* msg);
int relay_handle_group_vote(relay_server_t* server, int client_index, message_t* msg);
int relay_handle_group_leave(relay_server_t* server, int client_index, message_t* msg);
int relay_handle_group_invite(relay_server_t* server, int client_index, message_t* msg);

// Utilities
int relay_send_vote_request_to_members(relay_server_t* server, group_t* group,
                                       pending_join_t* pending);
int relay_send_group_info(relay_server_t* server, int client_index, group_t* group);

#endif // P2P_RELAY_HANDLERS_GROUP_H