#ifndef P2P_DHT_PENDING_H
#define P2P_DHT_PENDING_H

#include "dht_types.h"

/*  ============================================
    DHT PENDING REQUEST API

    Note: Manages async request/reply matching.
    Each outgoing RPC gets a pending slot; incoming replies
    fulfill the slot by transaction_id.
    ============================================ */

// Allocate a pending request slot for a new outgoing RPC.
// Returns a pointer to the slot, or NULL if all slots are in use.
dht_pending_request_t* dht_pending_alloc(dht_context_t* ctx,
                                          uint32_t txn_id,
                                          dht_msg_type_t expected,
                                          const char* ip, uint16_t port);

// Find a pending request by transaction_id.
// Caller must hold ctx->pending_mutex or accept races.
dht_pending_request_t* dht_pending_find(dht_context_t* ctx, uint32_t txn_id);

// Release a pending request slot.
void dht_pending_free(dht_pending_request_t* req);

// Block until the request is fulfilled or timeout_ms expires.
// Returns 0 if response received, -1 on timeout.
// Increments ctx->timeouts on timeout.
int dht_pending_wait(dht_context_t* ctx, dht_pending_request_t* req,
                      int timeout_ms);

// Free all slots whose sent_at exceeds 2× DHT_REQUEST_TIMEOUT_MS.
void dht_pending_expire(dht_context_t* ctx);

#endif // P2P_DHT_PENDING_H