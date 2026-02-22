#include "dht_messages.h"

#include <string.h>

/*  Function: dht_next_txn_id
    Description:
    Atomically increments and returns ctx->next_transaction_id.

    Parameters:
    - ctx: DHT context.

    Returns:
    - The next unique transaction ID.
*/
uint32_t dht_next_txn_id(dht_context_t* ctx) {
    return __sync_fetch_and_add(&ctx->next_transaction_id, 1);
}

/*  Function: dht_fill_header
    Description:
    Populates a dht_msg_header_t with standard fields.

    Parameters:
    - hdr: Header to fill.
    - ctx: DHT context (for self ID and txn ID).
    - type: Message type enum value.

    Steps:
    1. Zeros the header.
    2. Sets type, version=1, sender_id from routing table, and a new transaction_id.
*/
void dht_fill_header(dht_msg_header_t* hdr, dht_context_t* ctx,
                      dht_msg_type_t type) {
    memset(hdr, 0, sizeof(dht_msg_header_t));
    hdr->type = (uint8_t)type;
    hdr->version = 1;
    hdr->sender_id = ctx->routing_table.self_id;
    hdr->transaction_id = dht_next_txn_id(ctx);
}