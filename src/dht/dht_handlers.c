#define _POSIX_C_SOURCE 200809L
#include "dht_handlers.h"
#include "dht_net.h"
#include "dht_pending.h"
#include "dht_messages.h"
#include "../common/logging.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

// ============================================
// TIMESTAMP HELPER
// ============================================

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

// ============================================
// INDIVIDUAL HANDLERS
// ============================================

/*  Function: handle_ping
    Description:
    Replies with a PONG preserving the caller's transaction ID.

    Steps:
    1. Builds a PONG message with the incoming transaction_id.
    2. Sends it back to from_ip:from_port.
*/
static void handle_ping(dht_context_t* ctx, const dht_msg_header_t* hdr,
                         const char* from_ip, uint16_t from_port) {
    dht_msg_pong_t pong;
    memset(&pong, 0, sizeof(pong));
    pong.header.type = (uint8_t)DHT_MSG_PONG;
    pong.header.version = 1;
    pong.header.sender_id = ctx->routing_table.self_id;
    pong.header.transaction_id = hdr->transaction_id;

    dht_send_to(ctx, &pong, sizeof(pong), from_ip, from_port);
    LOG_TRACE("dht: PING from %s:%d → PONG (txn=%u)",
              from_ip, from_port, hdr->transaction_id);
}

/*  Function: handle_pong
    Description:
    Marks the sender as seen and fulfills the matching pending request.

    Steps:
    1. Calls routing_table_mark_seen.
    2. Finds the pending request by transaction_id and sets responded=true.
*/
static void handle_pong(dht_context_t* ctx, const dht_msg_header_t* hdr,
                         const char* from_ip, uint16_t from_port) {
    routing_table_mark_seen(&ctx->routing_table, &hdr->sender_id);

    pthread_mutex_lock(&ctx->pending_mutex);
    dht_pending_request_t* req = dht_pending_find(ctx, hdr->transaction_id);
    if (req) {
        req->responded = true;
        req->target_id = hdr->sender_id;
    }
    pthread_mutex_unlock(&ctx->pending_mutex);

    LOG_TRACE("dht: PONG from %s:%d (txn=%u)",
              from_ip, from_port, hdr->transaction_id);
}

/*  Function: handle_find_node
    Description:
    Responds with the k closest nodes to the requested target.

    Steps:
    1. Extracts the target from the message.
    2. Queries routing_table_find_closest.
    3. Builds and sends a FIND_NODE_REPLY with the results.
*/
static void handle_find_node(dht_context_t* ctx, const uint8_t* buf, size_t len,
                              const char* from_ip, uint16_t from_port) {
    if (len < sizeof(dht_msg_find_node_t)) return;

    const dht_msg_find_node_t* msg = (const dht_msg_find_node_t*)buf;

    dht_node_t closest[DHT_K_BUCKET_SIZE];
    int count = routing_table_find_closest(&ctx->routing_table,
                                            &msg->target,
                                            closest, DHT_K_BUCKET_SIZE);

    dht_msg_find_node_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    reply.header.type = (uint8_t)DHT_MSG_FIND_NODE_REPLY;
    reply.header.version = 1;
    reply.header.sender_id = ctx->routing_table.self_id;
    reply.header.transaction_id = msg->header.transaction_id;
    reply.count = (uint8_t)count;

    for (int i = 0; i < count; i++) {
        reply.nodes[i].id = closest[i].id;
        strncpy(reply.nodes[i].ip, closest[i].ip, sizeof(reply.nodes[i].ip) - 1);
        reply.nodes[i].port = closest[i].port;
    }

    size_t reply_len = sizeof(dht_msg_header_t) + 1 +
                       (size_t)count * sizeof(dht_compact_node_t);
    dht_send_to(ctx, &reply, reply_len, from_ip, from_port);

    LOG_TRACE("dht: FIND_NODE from %s:%d → %d closest nodes (txn=%u)",
              from_ip, from_port, count, msg->header.transaction_id);
}

/*  Function: handle_find_node_reply
    Description:
    Adds discovered nodes to the routing table and fulfills the pending request.

    Steps:
    1. Parses node count and compact node array from the buffer.
    2. Adds each discovered node to the routing table.
    3. Copies the raw response into the pending request's buffer.
*/
static void handle_find_node_reply(dht_context_t* ctx, const uint8_t* buf,
                                    size_t len, const dht_msg_header_t* hdr) {
    if (len < sizeof(dht_msg_header_t) + 1) return;

    uint8_t count = buf[sizeof(dht_msg_header_t)];
    size_t expected = sizeof(dht_msg_header_t) + 1 +
                      (size_t)count * sizeof(dht_compact_node_t);
    if (len < expected || count > DHT_K_BUCKET_SIZE) return;

    const dht_compact_node_t* nodes =
        (const dht_compact_node_t*)(buf + sizeof(dht_msg_header_t) + 1);

    for (int i = 0; i < count; i++) {
        dht_node_t node;
        memset(&node, 0, sizeof(node));
        node.id = nodes[i].id;
        strncpy(node.ip, nodes[i].ip, sizeof(node.ip) - 1);
        node.port = nodes[i].port;
        node.last_seen = get_timestamp_ms();
        node.is_good = true;
        routing_table_add(&ctx->routing_table, &node);
    }

    pthread_mutex_lock(&ctx->pending_mutex);
    dht_pending_request_t* req = dht_pending_find(ctx, hdr->transaction_id);
    if (req) {
        req->responded = true;
        size_t copy = len < sizeof(req->response_buf) ? len : sizeof(req->response_buf);
        memcpy(req->response_buf, buf, copy);
        req->response_len = copy;
    }
    pthread_mutex_unlock(&ctx->pending_mutex);

    LOG_TRACE("dht: FIND_NODE_REPLY → %d nodes discovered (txn=%u)",
              count, hdr->transaction_id);
}

/*  Function: handle_find_value
    Description:
    If the key is in local storage, replies with the value.
    Otherwise replies with the k closest nodes (like FIND_NODE).

    Steps:
    1. Attempts dht_storage_get for the key.
    2. If found: builds FIND_VALUE_REPLY with found=1 and value data.
    3. If not found: queries closest nodes and builds reply with found=0 and nodes.
*/
static void handle_find_value(dht_context_t* ctx, const uint8_t* buf, size_t len,
                               const char* from_ip, uint16_t from_port) {
    if (len < sizeof(dht_msg_find_value_t)) return;

    const dht_msg_find_value_t* msg = (const dht_msg_find_value_t*)buf;

    uint8_t value_buf[DHT_MAX_VALUE_SIZE];
    size_t value_len = sizeof(value_buf);

    if (dht_storage_get(&ctx->storage, &msg->key, value_buf, &value_len) == 0) {
        size_t reply_size = sizeof(dht_msg_find_value_reply_t) + value_len;
        uint8_t* reply_buf = malloc(reply_size);
        if (!reply_buf) return;

        dht_msg_find_value_reply_t* reply = (dht_msg_find_value_reply_t*)reply_buf;
        memset(reply, 0, sizeof(dht_msg_find_value_reply_t));
        reply->header.type = (uint8_t)DHT_MSG_FIND_VALUE_REPLY;
        reply->header.version = 1;
        reply->header.sender_id = ctx->routing_table.self_id;
        reply->header.transaction_id = msg->header.transaction_id;
        reply->found = 1;
        reply->value_len = (uint32_t)value_len;
        memcpy(reply_buf + sizeof(dht_msg_find_value_reply_t), value_buf, value_len);

        dht_send_to(ctx, reply_buf, reply_size, from_ip, from_port);
        free(reply_buf);

        LOG_TRACE("dht: FIND_VALUE from %s:%d → found (%zu bytes)",
                  from_ip, from_port, value_len);
    } else {
        dht_node_t closest[DHT_K_BUCKET_SIZE];
        int count = routing_table_find_closest(&ctx->routing_table,
                                                &msg->key,
                                                closest, DHT_K_BUCKET_SIZE);

        size_t reply_size = sizeof(dht_msg_find_value_reply_t) +
                            (size_t)count * sizeof(dht_compact_node_t);
        uint8_t* reply_buf = malloc(reply_size);
        if (!reply_buf) return;

        dht_msg_find_value_reply_t* reply = (dht_msg_find_value_reply_t*)reply_buf;
        memset(reply, 0, sizeof(dht_msg_find_value_reply_t));
        reply->header.type = (uint8_t)DHT_MSG_FIND_VALUE_REPLY;
        reply->header.version = 1;
        reply->header.sender_id = ctx->routing_table.self_id;
        reply->header.transaction_id = msg->header.transaction_id;
        reply->found = 0;
        reply->value_len = (uint32_t)count;

        dht_compact_node_t* nodes_out =
            (dht_compact_node_t*)(reply_buf + sizeof(dht_msg_find_value_reply_t));
        for (int i = 0; i < count; i++) {
            nodes_out[i].id = closest[i].id;
            strncpy(nodes_out[i].ip, closest[i].ip, sizeof(nodes_out[i].ip) - 1);
            nodes_out[i].port = closest[i].port;
        }

        dht_send_to(ctx, reply_buf, reply_size, from_ip, from_port);
        free(reply_buf);

        LOG_TRACE("dht: FIND_VALUE from %s:%d → not found, returning %d nodes",
                  from_ip, from_port, count);
    }
}

/*  Function: handle_find_value_reply
    Description:
    Processes a FIND_VALUE_REPLY: either extracts the found value or adds
    returned nodes to the routing table. Fulfills the pending request.

    Steps:
    1. If found==1: copies raw response into pending request buffer.
    2. If found==0: parses compact nodes, adds to routing table, copies response.
*/
static void handle_find_value_reply(dht_context_t* ctx, const uint8_t* buf,
                                     size_t len, const dht_msg_header_t* hdr) {
    if (len < sizeof(dht_msg_find_value_reply_t)) return;

    const dht_msg_find_value_reply_t* reply = (const dht_msg_find_value_reply_t*)buf;

    if (reply->found == 1) {
        pthread_mutex_lock(&ctx->pending_mutex);
        dht_pending_request_t* req = dht_pending_find(ctx, hdr->transaction_id);
        if (req) {
            req->responded = true;
            size_t copy = len < sizeof(req->response_buf) ? len : sizeof(req->response_buf);
            memcpy(req->response_buf, buf, copy);
            req->response_len = copy;
        }
        pthread_mutex_unlock(&ctx->pending_mutex);

        LOG_DEBUG("dht: FIND_VALUE_REPLY → value found (%u bytes)", reply->value_len);
    } else {
        int count = (int)reply->value_len;
        if (count > DHT_K_BUCKET_SIZE) count = DHT_K_BUCKET_SIZE;

        const dht_compact_node_t* nodes =
            (const dht_compact_node_t*)(buf + sizeof(dht_msg_find_value_reply_t));

        size_t expected = sizeof(dht_msg_find_value_reply_t) +
                          (size_t)count * sizeof(dht_compact_node_t);
        if (len >= expected) {
            for (int i = 0; i < count; i++) {
                dht_node_t node;
                memset(&node, 0, sizeof(node));
                node.id = nodes[i].id;
                strncpy(node.ip, nodes[i].ip, sizeof(node.ip) - 1);
                node.port = nodes[i].port;
                node.last_seen = get_timestamp_ms();
                node.is_good = true;
                routing_table_add(&ctx->routing_table, &node);
            }
        }

        pthread_mutex_lock(&ctx->pending_mutex);
        dht_pending_request_t* req = dht_pending_find(ctx, hdr->transaction_id);
        if (req) {
            req->responded = true;
            size_t copy = len < sizeof(req->response_buf) ? len : sizeof(req->response_buf);
            memcpy(req->response_buf, buf, copy);
            req->response_len = copy;
        }
        pthread_mutex_unlock(&ctx->pending_mutex);

        LOG_TRACE("dht: FIND_VALUE_REPLY → not found, %d nodes returned", count);
    }
}

/*  Function: handle_store
    Description:
    Stores the key-value pair from the message into local storage and sends an ACK.

    Steps:
    1. Validates message length against declared value_len.
    2. Calls dht_storage_put.
    3. Sends a STORE_ACK with the same transaction_id.
*/
static void handle_store(dht_context_t* ctx, const uint8_t* buf, size_t len,
                          const char* from_ip, uint16_t from_port) {
    if (len < sizeof(dht_msg_store_t)) return;

    const dht_msg_store_t* msg = (const dht_msg_store_t*)buf;

    size_t expected = sizeof(dht_msg_store_t) + msg->value_len;
    if (len < expected) {
        LOG_WARN("dht: STORE message truncated (%zu < %zu)", len, expected);
        return;
    }

    const uint8_t* value_data = buf + sizeof(dht_msg_store_t);

    int result = dht_storage_put(&ctx->storage, &msg->key,
                                  value_data, msg->value_len,
                                  &msg->header.sender_id,
                                  msg->ttl_seconds);

    dht_msg_header_t ack;
    memset(&ack, 0, sizeof(ack));
    ack.type = (uint8_t)DHT_MSG_STORE_ACK;
    ack.version = 1;
    ack.sender_id = ctx->routing_table.self_id;
    ack.transaction_id = msg->header.transaction_id;
    dht_send_to(ctx, &ack, sizeof(ack), from_ip, from_port);

    LOG_TRACE("dht: STORE from %s:%d (%u bytes, TTL=%us) → %s",
              from_ip, from_port, msg->value_len, msg->ttl_seconds,
              result == 0 ? "ACK" : "FAIL");
}

/*  Function: handle_store_ack
    Description:
    Fulfills the pending request for a STORE operation.
*/
static void handle_store_ack(dht_context_t* ctx, const dht_msg_header_t* hdr) {
    pthread_mutex_lock(&ctx->pending_mutex);
    dht_pending_request_t* req = dht_pending_find(ctx, hdr->transaction_id);
    if (req) {
        req->responded = true;
    }
    pthread_mutex_unlock(&ctx->pending_mutex);

    LOG_TRACE("dht: STORE_ACK (txn=%u)", hdr->transaction_id);
}

// ============================================
// MAIN DISPATCHER
// ============================================

/*  Function: dht_handle_message
    Description:
    Validates the incoming datagram header, adds/updates the sender in the
    routing table, then dispatches to the type-specific handler.

    Parameters:
    - ctx: DHT context.
    - buf: Raw received bytes.
    - len: Number of bytes received.
    - from_ip: Sender IPv4 address string.
    - from_port: Sender port.

    Steps:
    1. Validates minimum length and protocol version.
    2. Increments messages_received.
    3. Upserts sender into the routing table.
    4. Switches on hdr->type and calls the matching handler.
*/
void dht_handle_message(dht_context_t* ctx, const uint8_t* buf, size_t len,
                         const char* from_ip, uint16_t from_port) {
    if (len < sizeof(dht_msg_header_t)) {
        LOG_TRACE("dht: Ignoring short message (%zu bytes) from %s:%d",
                  len, from_ip, from_port);
        return;
    }

    const dht_msg_header_t* hdr = (const dht_msg_header_t*)buf;

    if (hdr->version != 1) {
        LOG_WARN("dht: Unknown protocol version %d from %s:%d",
                 hdr->version, from_ip, from_port);
        return;
    }

    ctx->messages_received++;

    // Add/update sender in routing table
    dht_node_t sender;
    memset(&sender, 0, sizeof(sender));
    sender.id = hdr->sender_id;
    strncpy(sender.ip, from_ip, sizeof(sender.ip) - 1);
    sender.port = from_port;
    sender.last_seen = get_timestamp_ms();
    sender.is_good = true;
    sender.failed_pings = 0;
    routing_table_add(&ctx->routing_table, &sender);

    switch ((dht_msg_type_t)hdr->type) {
        case DHT_MSG_PING:
            handle_ping(ctx, hdr, from_ip, from_port);
            break;
        case DHT_MSG_PONG:
            handle_pong(ctx, hdr, from_ip, from_port);
            break;
        case DHT_MSG_FIND_NODE:
            handle_find_node(ctx, buf, len, from_ip, from_port);
            break;
        case DHT_MSG_FIND_NODE_REPLY:
            handle_find_node_reply(ctx, buf, len, hdr);
            break;
        case DHT_MSG_FIND_VALUE:
            handle_find_value(ctx, buf, len, from_ip, from_port);
            break;
        case DHT_MSG_FIND_VALUE_REPLY:
            handle_find_value_reply(ctx, buf, len, hdr);
            break;
        case DHT_MSG_STORE:
            handle_store(ctx, buf, len, from_ip, from_port);
            break;
        case DHT_MSG_STORE_ACK:
            handle_store_ack(ctx, hdr);
            break;
        default:
            LOG_WARN("dht: Unknown message type 0x%02x from %s:%d",
                     hdr->type, from_ip, from_port);
            break;
    }
}