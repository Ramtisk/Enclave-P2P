#define _POSIX_C_SOURCE 200809L
#include "dht_lookup.h"
#include "dht_net.h"
#include "dht_pending.h"
#include "dht_messages.h"
#include "../common/logging.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*  Function: dht_ping
    Description:
    Sends a PING to ip:port and blocks until a PONG is received or timeout.

    Parameters:
    - ctx: DHT context.
    - ip: Target IPv4 address.
    - port: Target port.

    Returns:
    - 0 if PONG received within DHT_PING_TIMEOUT_MS.
    - -1 on timeout.

    Steps:
    1. Builds a PING message.
    2. Allocates a pending request expecting PONG.
    3. Sends the message.
    4. Waits for the pending request to be fulfilled.
    5. Frees the pending slot.
*/
int dht_ping(dht_context_t* ctx, const char* ip, uint16_t port) {
    if (!ctx || !ip) return -1;

    dht_msg_ping_t msg;
    memset(&msg, 0, sizeof(msg));
    dht_fill_header(&msg.header, ctx, DHT_MSG_PING);

    dht_pending_request_t* req = dht_pending_alloc(ctx, msg.header.transaction_id,
                                                    DHT_MSG_PONG, ip, port);

    if (dht_send_to(ctx, &msg, sizeof(msg), ip, port) != 0) {
        if (req) dht_pending_free(req);
        return -1;
    }

    int result = dht_pending_wait(ctx, req, DHT_PING_TIMEOUT_MS);

    if (result != 0) {
        LOG_TRACE("dht: PING to %s:%d timed out", ip, port);
    }

    if (req) dht_pending_free(req);
    return result;
}

/*  Function: dht_find_node
    Description:
    Performs an iterative Kademlia FIND_NODE lookup for the target ID.

    Parameters:
    - ctx: DHT context.
    - target: The node ID to search for.
    - results: Output array for closest nodes found.
    - max_results: Maximum entries to return.

    Returns:
    - Number of results found (0 if routing table is empty).

    Steps:
    1. Seeds shortlist with k closest known nodes.
    2. For up to 5 rounds:
       a. Sends FIND_NODE to α closest unqueried nodes.
       b. Waits for replies (handlers add discovered nodes to routing table).
    3. Returns k closest from the (now-updated) routing table.
    4. Increments lookups_completed.
*/
int dht_find_node(dht_context_t* ctx, const dht_node_id_t* target,
                  dht_node_t* results, int max_results) {
    if (!ctx || !target || !results || max_results <= 0) return 0;

    dht_node_t shortlist[DHT_K_BUCKET_SIZE * 3];
    int shortlist_count = routing_table_find_closest(
        &ctx->routing_table, target, shortlist, DHT_K_BUCKET_SIZE);

    if (shortlist_count == 0) {
        LOG_DEBUG("dht: find_node — routing table empty, no results");
        return 0;
    }

    dht_node_id_t queried[DHT_K_BUCKET_SIZE * 4];
    int queried_count = 0;

    int max_rounds = 5;

    for (int round = 0; round < max_rounds; round++) {
        int queries_sent = 0;
        dht_pending_request_t* round_reqs[DHT_ALPHA];
        memset(round_reqs, 0, sizeof(round_reqs));

        for (int i = 0; i < shortlist_count && queries_sent < DHT_ALPHA; i++) {
            bool already = false;
            for (int q = 0; q < queried_count; q++) {
                if (dht_id_equal(&queried[q], &shortlist[i].id)) {
                    already = true;
                    break;
                }
            }
            if (already) continue;

            if (queried_count < DHT_K_BUCKET_SIZE * 4) {
                queried[queried_count++] = shortlist[i].id;
            }

            dht_msg_find_node_t msg;
            memset(&msg, 0, sizeof(msg));
            dht_fill_header(&msg.header, ctx, DHT_MSG_FIND_NODE);
            msg.target = *target;

            dht_pending_request_t* req = dht_pending_alloc(
                ctx, msg.header.transaction_id,
                DHT_MSG_FIND_NODE_REPLY,
                shortlist[i].ip, shortlist[i].port);

            if (dht_send_to(ctx, &msg, sizeof(msg),
                             shortlist[i].ip, shortlist[i].port) == 0) {
                round_reqs[queries_sent] = req;
                queries_sent++;
            } else if (req) {
                dht_pending_free(req);
            }
        }

        if (queries_sent == 0) break;

        for (int i = 0; i < queries_sent; i++) {
            if (round_reqs[i]) {
                dht_pending_wait(ctx, round_reqs[i], DHT_REQUEST_TIMEOUT_MS);
                dht_pending_free(round_reqs[i]);
            }
        }

        usleep(50000); // 50ms for handlers to process
    }

    int count = routing_table_find_closest(&ctx->routing_table, target,
                                            results, max_results);

    ctx->lookups_completed++;
    LOG_DEBUG("dht: find_node complete — %d results", count);
    return count;
}

/*  Function: dht_find_value
    Description:
    Iterative Kademlia FIND_VALUE lookup. Checks local storage first,
    then queries progressively closer nodes.

    Parameters:
    - ctx: DHT context.
    - key: The key to look up.
    - value_out: Buffer for the found value.
    - value_len: In: buffer size. Out: actual value size.

    Returns:
    - 0 if value found (locally or remotely), -1 if not found.

    Steps:
    1. Checks local storage.
    2. Seeds closest list from routing table.
    3. For up to 5 rounds, sends FIND_VALUE to α unqueried closest nodes.
    4. If any reply has found==1, extracts value, caches locally, and returns.
    5. Otherwise refreshes closest list and continues.
*/
int dht_find_value(dht_context_t* ctx, const dht_node_id_t* key,
                   uint8_t* value_out, size_t* value_len) {
    if (!ctx || !key || !value_out || !value_len) return -1;

    // Check local storage first
    if (dht_storage_get(&ctx->storage, key, value_out, value_len) == 0) {
        LOG_DEBUG("dht: find_value — found locally");
        return 0;
    }

    dht_node_t closest[DHT_K_BUCKET_SIZE];
    int closest_count = routing_table_find_closest(
        &ctx->routing_table, key, closest, DHT_K_BUCKET_SIZE);

    if (closest_count == 0) {
        LOG_DEBUG("dht: find_value — no nodes in routing table");
        return -1;
    }

    dht_node_id_t queried[DHT_K_BUCKET_SIZE * 4];
    int queried_count = 0;

    for (int round = 0; round < 5; round++) {
        int queries_sent = 0;
        dht_pending_request_t* round_reqs[DHT_ALPHA];
        memset(round_reqs, 0, sizeof(round_reqs));

        for (int i = 0; i < closest_count && queries_sent < DHT_ALPHA; i++) {
            bool already = false;
            for (int q = 0; q < queried_count; q++) {
                if (dht_id_equal(&queried[q], &closest[i].id)) {
                    already = true;
                    break;
                }
            }
            if (already) continue;

            if (queried_count < DHT_K_BUCKET_SIZE * 4) {
                queried[queried_count++] = closest[i].id;
            }

            dht_msg_find_value_t msg;
            memset(&msg, 0, sizeof(msg));
            dht_fill_header(&msg.header, ctx, DHT_MSG_FIND_VALUE);
            msg.key = *key;

            dht_pending_request_t* req = dht_pending_alloc(
                ctx, msg.header.transaction_id,
                DHT_MSG_FIND_VALUE_REPLY,
                closest[i].ip, closest[i].port);

            if (dht_send_to(ctx, &msg, sizeof(msg),
                             closest[i].ip, closest[i].port) == 0) {
                round_reqs[queries_sent] = req;
                queries_sent++;
            } else if (req) {
                dht_pending_free(req);
            }
        }

        if (queries_sent == 0) break;

        for (int i = 0; i < queries_sent; i++) {
            if (!round_reqs[i]) continue;

            if (dht_pending_wait(ctx, round_reqs[i], DHT_REQUEST_TIMEOUT_MS) == 0) {
                pthread_mutex_lock(&ctx->pending_mutex);
                if (round_reqs[i]->response_len >= sizeof(dht_msg_find_value_reply_t)) {
                    const dht_msg_find_value_reply_t* reply =
                        (const dht_msg_find_value_reply_t*)round_reqs[i]->response_buf;

                    if (reply->found == 1 && reply->value_len > 0) {
                        size_t vlen = reply->value_len;
                        size_t data_offset = sizeof(dht_msg_find_value_reply_t);

                        if (data_offset + vlen <= round_reqs[i]->response_len &&
                            vlen <= *value_len) {
                            memcpy(value_out,
                                   round_reqs[i]->response_buf + data_offset,
                                   vlen);
                            *value_len = vlen;

                            // Cache locally
                            dht_storage_put(&ctx->storage, key, value_out, vlen,
                                           &ctx->routing_table.self_id,
                                           DHT_DEFAULT_TTL_S);

                            pthread_mutex_unlock(&ctx->pending_mutex);

                            for (int j = i; j < queries_sent; j++) {
                                if (round_reqs[j]) dht_pending_free(round_reqs[j]);
                            }

                            ctx->lookups_completed++;
                            LOG_DEBUG("dht: find_value — found remotely (%zu bytes)", vlen);
                            return 0;
                        }
                    }
                }
                pthread_mutex_unlock(&ctx->pending_mutex);
            }

            dht_pending_free(round_reqs[i]);
        }

        closest_count = routing_table_find_closest(
            &ctx->routing_table, key, closest, DHT_K_BUCKET_SIZE);
    }

    ctx->lookups_completed++;
    LOG_DEBUG("dht: find_value — not found after iterative lookup");
    return -1;
}

/*  Function: dht_store
    Description:
    Stores a key-value pair locally and on the k closest nodes.

    Parameters:
    - ctx: DHT context.
    - key: 160-bit key.
    - value: Value data.
    - value_len: Value length (max DHT_MAX_VALUE_SIZE).
    - ttl_seconds: Time-to-live (0 = default).

    Returns:
    - 0 on success (even if no remote nodes are reachable).

    Steps:
    1. Stores locally via dht_storage_put.
    2. Finds DHT_REPLICATION_FACTOR closest nodes.
    3. Sends STORE to each, waiting briefly for ACKs.
    4. Logs the number of successful replications.
*/
int dht_store(dht_context_t* ctx, const dht_node_id_t* key,
              const uint8_t* value, size_t value_len,
              uint32_t ttl_seconds) {
    if (!ctx || !key || !value || value_len == 0) return -1;
    if (value_len > DHT_MAX_VALUE_SIZE) return -1;
    if (ttl_seconds == 0) ttl_seconds = DHT_DEFAULT_TTL_S;

    // Store locally
    dht_storage_put(&ctx->storage, key, value, value_len,
                    &ctx->routing_table.self_id, ttl_seconds);

    // Find closest nodes
    dht_node_t closest[DHT_K_BUCKET_SIZE];
    int count = routing_table_find_closest(&ctx->routing_table, key,
                                            closest, DHT_REPLICATION_FACTOR);

    if (count == 0) {
        LOG_DEBUG("dht: store — no peers, stored locally only");
        return 0;
    }

    // Build STORE message
    size_t msg_size = sizeof(dht_msg_store_t) + value_len;
    uint8_t* msg_buf = malloc(msg_size);
    if (!msg_buf) return -1;

    int successful = 0;

    for (int i = 0; i < count; i++) {
        dht_msg_store_t* msg = (dht_msg_store_t*)msg_buf;
        memset(msg, 0, sizeof(dht_msg_store_t));
        dht_fill_header(&msg->header, ctx, DHT_MSG_STORE);
        msg->key = *key;
        msg->value_len = (uint32_t)value_len;
        msg->ttl_seconds = ttl_seconds;
        memcpy(msg_buf + sizeof(dht_msg_store_t), value, value_len);

        dht_pending_request_t* req = dht_pending_alloc(
            ctx, msg->header.transaction_id,
            DHT_MSG_STORE_ACK,
            closest[i].ip, closest[i].port);

        if (dht_send_to(ctx, msg_buf, msg_size,
                         closest[i].ip, closest[i].port) == 0) {
            if (req && dht_pending_wait(ctx, req, 2000) == 0) {
                successful++;
            }
        }

        if (req) dht_pending_free(req);
    }

    free(msg_buf);

    LOG_DEBUG("dht: Stored value (%zu bytes, TTL=%us) on %d/%d nodes",
              value_len, ttl_seconds, successful, count);
    return 0;
}