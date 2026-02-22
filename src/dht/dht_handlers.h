#ifndef P2P_DHT_HANDLERS_H
#define P2P_DHT_HANDLERS_H

#include "dht_types.h"

/*  ============================================
    DHT INCOMING MESSAGE HANDLER API

    Note: Dispatches received UDP datagrams to the appropriate handler
    based on the message type field.
    ============================================ */

// Main dispatcher. Validates the header, updates the routing table
// with the sender, then calls the type-specific handler.
void dht_handle_message(dht_context_t* ctx, const uint8_t* buf, size_t len,
                         const char* from_ip, uint16_t from_port);

#endif // P2P_DHT_HANDLERS_H