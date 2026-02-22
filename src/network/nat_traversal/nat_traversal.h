#ifndef P2P_NAT_TRAVERSAL_H
#define P2P_NAT_TRAVERSAL_H

#include "nat_types.h"
#include "nat_discovery.h"
#include "nat_punch.h"
#include "nat_relay.h"

/*  ============================================
    NAT TRAVERSAL — TOP-LEVEL API

    Note: Lifecycle (init/cleanup) and peer connection lookup.
    All sub-operations are in dedicated headers:
    - nat_discovery.h → STUN + relay discovery
    - nat_punch.h     → UDP/TCP hole punch
    - nat_relay.h     → Relay proxy fallback
    ============================================ */

// Lifecycle
int  nat_manager_init(nat_manager_t* mgr, const char* relay_host, uint16_t relay_port);
void nat_manager_cleanup(nat_manager_t* mgr);

// Get existing connected fd for a peer, or -1.
int nat_get_peer_connection(nat_manager_t* mgr, const char* peer_id);

#endif // P2P_NAT_TRAVERSAL_H