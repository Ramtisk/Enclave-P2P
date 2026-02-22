#ifndef P2P_DHT_MESSAGES_H
#define P2P_DHT_MESSAGES_H

#include "dht_types.h"

/*  ============================================
    DHT MESSAGE BUILDING API

    Note: Transaction ID generation and message header construction.
    ============================================ */

// Generate the next transaction ID (atomic increment).
uint32_t dht_next_txn_id(dht_context_t* ctx);

// Fill a message header with type, version, sender_id, and a new transaction ID.
void dht_fill_header(dht_msg_header_t* hdr, dht_context_t* ctx,
                      dht_msg_type_t type);

#endif // P2P_DHT_MESSAGES_H