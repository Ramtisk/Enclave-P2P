#ifndef P2P_CLIENT_NAT_H
#define P2P_CLIENT_NAT_H

#include "client_types.h"

/*  ============================================
    CLIENT NAT OPERATIONS API
    ============================================ */

int client_nat_discover(p2p_client_t* client);
int client_nat_punch(p2p_client_t* client, const char* peer_id);
int client_connect_to_peer(p2p_client_t* client, const char* peer_id,
                           const char* peer_ip, uint16_t peer_port);

#endif // P2P_CLIENT_NAT_H