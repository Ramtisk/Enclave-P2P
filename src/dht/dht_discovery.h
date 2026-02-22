#ifndef P2P_DHT_DISCOVERY_H
#define P2P_DHT_DISCOVERY_H

#include "dht_types.h"

/*  ============================================
    DHT PEER DISCOVERY CONVENIENCE API

    Note: Higher-level functions for announcing and finding peers
    in a named group via the DHT.
    ============================================ */

// Store peer info (ip:port) under a key derived from group_id.
int dht_announce_peer(dht_context_t* ctx, const char* group_id,
                      const char* ip, uint16_t port);

// Find peers for a group by looking up the group key.
// Falls back to returning the k closest nodes if no announced value is found.
int dht_find_peers(dht_context_t* ctx, const char* group_id,
                   dht_node_t* peers_out, int max_peers);

#endif // P2P_DHT_DISCOVERY_H