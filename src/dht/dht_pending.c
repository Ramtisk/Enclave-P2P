#define _POSIX_C_SOURCE 200809L
#include "dht_pending.h"
#include "../common/logging.h"

#include <string.h>
#include <time.h>
#include <unistd.h>

// ============================================
// TIMESTAMP HELPER
// ============================================

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/*  Function: dht_pending_alloc
    Description:
    Finds a free pending-request slot, initializes it, and returns a pointer.

    Parameters:
    - ctx: DHT context (holds the pending array and mutex).
    - txn_id: Transaction ID for matching.
    - expected: The reply message type we expect.
    - ip: Target IP we're sending to.
    - port: Target port.

    Returns:
    - Pointer to the slot, or NULL if all DHT_MAX_PENDING slots are in use.

    Steps:
    1. Locks pending_mutex.
    2. Scans for the first slot with in_use == false.
    3. Initializes the slot and marks in_use = true.
    4. Unlocks and returns.
*/
dht_pending_request_t* dht_pending_alloc(dht_context_t* ctx,
                                          uint32_t txn_id,
                                          dht_msg_type_t expected,
                                          const char* ip, uint16_t port) {
    pthread_mutex_lock(&ctx->pending_mutex);

    for (int i = 0; i < DHT_MAX_PENDING; i++) {
        if (!ctx->pending[i].in_use) {
            dht_pending_request_t* req = &ctx->pending[i];
            memset(req, 0, sizeof(dht_pending_request_t));
            req->transaction_id = txn_id;
            req->expected_type = expected;
            req->sent_at = get_timestamp_ms();
            req->responded = false;
            req->in_use = true;
            if (ip) strncpy(req->target_ip, ip, sizeof(req->target_ip) - 1);
            req->target_port = port;

            pthread_mutex_unlock(&ctx->pending_mutex);
            return req;
        }
    }

    pthread_mutex_unlock(&ctx->pending_mutex);
    LOG_WARN("dht/pending: No free slots");
    return NULL;
}

/*  Function: dht_pending_find
    Description:
    Searches the pending array for a slot matching the given transaction ID.

    Parameters:
    - ctx: DHT context.
    - txn_id: Transaction ID to match.

    Returns:
    - Pointer to the matching slot, or NULL.

    Note: Caller should hold ctx->pending_mutex if thread safety is required.
*/
dht_pending_request_t* dht_pending_find(dht_context_t* ctx, uint32_t txn_id) {
    for (int i = 0; i < DHT_MAX_PENDING; i++) {
        if (ctx->pending[i].in_use &&
            ctx->pending[i].transaction_id == txn_id) {
            return &ctx->pending[i];
        }
    }
    return NULL;
}

/*  Function: dht_pending_free
    Description:
    Releases a pending request slot by setting in_use to false.

    Parameters:
    - req: Pointer to the slot.
*/
void dht_pending_free(dht_pending_request_t* req) {
    if (req) req->in_use = false;
}

/*  Function: dht_pending_wait
    Description:
    Busy-waits (with 10ms sleeps) until the request is fulfilled or the timeout expires.

    Parameters:
    - ctx: DHT context (for timeout stats).
    - req: The pending request to wait on.
    - timeout_ms: Maximum wait time in milliseconds.

    Returns:
    - 0 if req->responded became true before the deadline.
    - -1 on timeout (also increments ctx->timeouts).
*/
int dht_pending_wait(dht_context_t* ctx, dht_pending_request_t* req,
                      int timeout_ms) {
    if (!req) return -1;

    uint64_t deadline = get_timestamp_ms() + (uint64_t)timeout_ms;

    while (get_timestamp_ms() < deadline) {
        pthread_mutex_lock(&ctx->pending_mutex);
        bool done = req->responded;
        pthread_mutex_unlock(&ctx->pending_mutex);

        if (done) return 0;
        usleep(10000); // 10ms poll interval
    }

    ctx->timeouts++;
    return -1;
}

/*  Function: dht_pending_expire
    Description:
    Frees all pending slots that have been waiting longer than 2× DHT_REQUEST_TIMEOUT_MS.

    Parameters:
    - ctx: DHT context.
*/
void dht_pending_expire(dht_context_t* ctx) {
    uint64_t now = get_timestamp_ms();

    pthread_mutex_lock(&ctx->pending_mutex);
    for (int i = 0; i < DHT_MAX_PENDING; i++) {
        if (ctx->pending[i].in_use &&
            now - ctx->pending[i].sent_at > DHT_REQUEST_TIMEOUT_MS * 2) {
            ctx->pending[i].in_use = false;
        }
    }
    pthread_mutex_unlock(&ctx->pending_mutex);
}