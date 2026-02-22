#ifndef P2P_CLIENT_GROUPS_H
#define P2P_CLIENT_GROUPS_H

#include "client_types.h"

/*  ============================================
    CLIENT GROUP OPERATIONS API
    ============================================ */

int client_create_group(p2p_client_t* client, const char* group_name);
int client_join_group(p2p_client_t* client, const char* invite_token);
int client_leave_group(p2p_client_t* client);
int client_vote(p2p_client_t* client, bool approve);
int client_request_invite(p2p_client_t* client);

#endif // P2P_CLIENT_GROUPS_H