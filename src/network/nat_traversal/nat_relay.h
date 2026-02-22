#ifndef P2P_NAT_RELAY_H
#define P2P_NAT_RELAY_H

#include "nat_types.h"

/*  ============================================
    NAT RELAY FALLBACK API

    Note: Proxies data through the relay server for symmetric NAT peers.
    ============================================ */

// Send data to a peer via the relay as a proxy.
int nat_relay_send(nat_manager_t* mgr, int relay_fd,
                   const char* peer_id, const void* data, size_t len);

#endif // P2P_NAT_RELAY_H