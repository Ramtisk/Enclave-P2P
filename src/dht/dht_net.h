#ifndef P2P_DHT_NET_H
#define P2P_DHT_NET_H

#include "dht_types.h"

/*  ============================================
    DHT NETWORK API

    Note: UDP socket lifecycle and send helper.
    ============================================ */

// Create and bind UDP socket. Sets ctx->socket_fd.
// Returns 0 on success, -1 on failure.
int dht_net_open(dht_context_t* ctx, uint16_t port);

// Close the UDP socket.
void dht_net_close(dht_context_t* ctx);

// Send raw data to ip:port via the context's UDP socket.
// Increments ctx->messages_sent on success.
// Returns 0 on success, -1 on failure.
int dht_send_to(dht_context_t* ctx, const void* data, size_t len,
                const char* ip, uint16_t port);

#endif // P2P_DHT_NET_H