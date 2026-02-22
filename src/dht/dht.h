#ifndef P2P_DHT_H
#define P2P_DHT_H

#include "dht_types.h"
#include "dht_lookup.h"
#include "dht_discovery.h"
#include "dht_print.h"

/*  ============================================
    DHT TOP-LEVEL API

    Note: Lifecycle (init, start, stop, cleanup) and bootstrap.
    All other operations are accessed via the sub-module headers:
    - dht_lookup.h    → ping, find_node, find_value, store
    - dht_discovery.h → announce_peer, find_peers
    - dht_print.h     → print_status, msg_type_string
    ============================================ */

// Initialize DHT with a random node ID
int dht_init(dht_context_t* ctx, uint16_t port);

// Initialize with a specific node ID
int dht_init_with_id(dht_context_t* ctx, const dht_node_id_t* id, uint16_t port);

// Start listener and maintenance threads
int dht_start(dht_context_t* ctx);

// Stop all threads
void dht_stop(dht_context_t* ctx);

// Clean up all resources
void dht_cleanup(dht_context_t* ctx);

// Add a bootstrap node
int dht_add_bootstrap(dht_context_t* ctx, const char* ip, uint16_t port);

// Bootstrap into the network
int dht_bootstrap(dht_context_t* ctx);

#endif // P2P_DHT_H