#ifndef P2P_DHT_LOOKUP_H
#define P2P_DHT_LOOKUP_H

#include "dht_types.h"

/*  ============================================
    DHT LOOKUP API

    Note: Kademlia iterative lookup operations:
    PING, FIND_NODE, FIND_VALUE, STORE.
    ============================================ */

// Ping a node (blocking, waits for pong).
// Returns 0 if pong received, -1 on timeout.
int dht_ping(dht_context_t* ctx, const char* ip, uint16_t port);

// Iterative Kademlia FIND_NODE lookup.
// Returns k closest nodes to target in results array.
int dht_find_node(dht_context_t* ctx, const dht_node_id_t* target,
                  dht_node_t* results, int max_results);

// Iterative FIND_VALUE lookup.
// Returns 0 if value found (copied to value_out), -1 otherwise.
int dht_find_value(dht_context_t* ctx, const dht_node_id_t* key,
                   uint8_t* value_out, size_t* value_len);

// Store a key-value pair on the k closest nodes.
// Also stores locally.
int dht_store(dht_context_t* ctx, const dht_node_id_t* key,
              const uint8_t* value, size_t value_len,
              uint32_t ttl_seconds);

#endif // P2P_DHT_LOOKUP_H