#ifndef P2P_NAT_DISCOVERY_H
#define P2P_NAT_DISCOVERY_H

#include "nat_types.h"

/*  ============================================
    NAT DISCOVERY API

    Note: Discovers our public endpoint via STUN and/or relay.
    ============================================ */

// Send discovery request to relay server.
// Relay responds with MSG_NAT_INFO containing our public endpoint.
int nat_discover(nat_manager_t* mgr, int relay_socket_fd);

// Direct STUN discovery (no relay needed).
// Queries multiple STUN servers and determines NAT type heuristically.
int nat_stun_discover(nat_manager_t* mgr);

// Set NAT info from relay response.
void nat_set_info(nat_manager_t* mgr, const payload_nat_info_t* info);

// Get local IP by connecting a UDP socket to 8.8.8.8 and reading getsockname.
void nat_get_local_ip(char* ip, size_t len);

#endif // P2P_NAT_DISCOVERY_H