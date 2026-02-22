#ifndef P2P_DHT_TYPES_H
#define P2P_DHT_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>
#include "routing.h"
#include "storage.h"
#include "../common/config.h"

// ============================================
// DHT MESSAGE TYPES
// ============================================
typedef enum {
    DHT_MSG_PING = 0x40,
    DHT_MSG_PONG,
    DHT_MSG_FIND_NODE,
    DHT_MSG_FIND_NODE_REPLY,
    DHT_MSG_FIND_VALUE,
    DHT_MSG_FIND_VALUE_REPLY,
    DHT_MSG_STORE,
    DHT_MSG_STORE_ACK,
} dht_msg_type_t;

// ============================================
// DHT MESSAGE STRUCTURES
// ============================================

typedef struct __attribute__((packed)) {
    uint8_t type;                           // dht_msg_type_t
    uint8_t version;
    dht_node_id_t sender_id;
    uint32_t transaction_id;                // For matching request/reply
} dht_msg_header_t;

typedef struct __attribute__((packed)) {
    dht_msg_header_t header;
} dht_msg_ping_t;

typedef struct __attribute__((packed)) {
    dht_msg_header_t header;
} dht_msg_pong_t;

typedef struct __attribute__((packed)) {
    dht_msg_header_t header;
    dht_node_id_t target;                   // Looking for nodes close to this
} dht_msg_find_node_t;

typedef struct __attribute__((packed)) {
    dht_node_id_t id;
    char ip[46];
    uint16_t port;
} dht_compact_node_t;

typedef struct __attribute__((packed)) {
    dht_msg_header_t header;
    uint8_t count;
    dht_compact_node_t nodes[DHT_K_BUCKET_SIZE];
} dht_msg_find_node_reply_t;

typedef struct __attribute__((packed)) {
    dht_msg_header_t header;
    dht_node_id_t key;
} dht_msg_find_value_t;

typedef struct __attribute__((packed)) {
    dht_msg_header_t header;
    uint8_t found;                           // 1 = value found, 0 = returning nodes
    uint32_t value_len;
    // Followed by value data if found=1
    // Or dht_compact_node_t[] if found=0
} dht_msg_find_value_reply_t;

typedef struct __attribute__((packed)) {
    dht_msg_header_t header;
    dht_node_id_t key;
    uint32_t value_len;
    uint32_t ttl_seconds;
    // Followed by value data
} dht_msg_store_t;

// ============================================
// PENDING REQUEST (for async request/reply matching)
// ============================================
#define DHT_MAX_PENDING        256
#define DHT_REQUEST_TIMEOUT_MS 5000

typedef struct {
    uint32_t transaction_id;
    dht_msg_type_t expected_type;
    uint64_t sent_at;

    // Response storage
    bool responded;
    uint8_t response_buf[4096];
    size_t response_len;

    // Target info
    char target_ip[46];
    uint16_t target_port;
    dht_node_id_t target_id;

    bool in_use;
} dht_pending_request_t;

// ============================================
// DHT NODE CONTEXT
// ============================================
typedef struct {
    routing_table_t routing_table;
    dht_storage_t storage;

    char listen_ip[46];
    uint16_t listen_port;
    int socket_fd;

    bool running;
    pthread_t listen_thread;
    pthread_t maintenance_thread;
    pthread_mutex_t mutex;

    uint32_t next_transaction_id;

    // Pending requests for async matching
    dht_pending_request_t pending[DHT_MAX_PENDING];
    pthread_mutex_t pending_mutex;

    // Bootstrap nodes
    struct {
        char ip[46];
        uint16_t port;
    } bootstrap_nodes[16];
    int bootstrap_count;

    // Stats
    uint64_t messages_sent;
    uint64_t messages_received;
    uint64_t lookups_completed;
    uint64_t timeouts;
} dht_context_t;

#endif // P2P_DHT_TYPES_H