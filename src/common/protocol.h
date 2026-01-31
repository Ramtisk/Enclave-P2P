#ifndef P2P_PROTOCOL_H
#define P2P_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include "config.h"

// ============================================
// MESSAGE TYPES
// ============================================
typedef enum {
    // Connection management
    MSG_CONNECT     = 0x01,
    MSG_DISCONNECT  = 0x02,
    MSG_ACK         = 0x03,
    MSG_NACK        = 0x04,
    
    // Keep-alive
    MSG_PING        = 0x10,
    MSG_PONG        = 0x11,
    
    // Group management (Phase 2)
    MSG_GROUP_CREATE    = 0x20,
    MSG_GROUP_JOIN      = 0x21,
    MSG_GROUP_LEAVE     = 0x22,
    MSG_GROUP_VOTE      = 0x23,
    MSG_GROUP_INVITE    = 0x24,
    
    // File transfer (Phase 3)
    MSG_FILE_LIST       = 0x30,
    MSG_FILE_SEARCH     = 0x31,
    MSG_FILE_REQUEST    = 0x32,
    MSG_FILE_SHARD      = 0x33,
    MSG_FILE_ACK        = 0x34,
    
    // Relay specific
    MSG_RELAY_FORWARD   = 0x40,
    MSG_PEER_LIST       = 0x41
    
} message_type_t;

// ============================================
// MESSAGE HEADER
// ============================================
#define PROTOCOL_MAGIC 0x50325050  // "P2PP"
#define PROTOCOL_VERSION 1

typedef struct __attribute__((packed)) {
    uint32_t magic;              // PROTOCOL_MAGIC
    uint8_t  version;            // Protocol version
    uint8_t  type;               // message_type_t
    uint16_t flags;              // Reserved for future use
    uint32_t payload_length;     // Length of payload
    uint64_t timestamp;          // Unix timestamp in ms
    char     sender_id[MAX_ID_LENGTH];
    char     target_id[MAX_ID_LENGTH];  // Empty = broadcast/relay
} message_header_t;

// ============================================
// MESSAGE STRUCTURE
// ============================================
typedef struct __attribute__((packed)) {
    message_header_t header;
    uint8_t payload[MAX_PAYLOAD_SIZE];
} message_t;

// ============================================
// PAYLOAD STRUCTURES
// ============================================

// MSG_PING / MSG_PONG
typedef struct __attribute__((packed)) {
    uint64_t ping_time;
    uint32_t ping_id;
} payload_ping_t;

// MSG_CONNECT
typedef struct __attribute__((packed)) {
    char client_id[MAX_ID_LENGTH];
    char client_version[16];
    uint16_t listen_port;        // Port for P2P connections
} payload_connect_t;

// MSG_PEER_LIST
typedef struct __attribute__((packed)) {
    uint32_t peer_count;
    struct {
        char id[MAX_ID_LENGTH];
        char ip[46];             // IPv6 compatible
        uint16_t port;
        uint8_t online;
    } peers[MAX_CLIENTS];
} payload_peer_list_t;

// ============================================
// HELPER FUNCTIONS
// ============================================

static inline void message_header_init(message_header_t* header, message_type_t type) {
    memset(header, 0, sizeof(message_header_t));
    header->magic = PROTOCOL_MAGIC;
    header->version = PROTOCOL_VERSION;
    header->type = (uint8_t)type;
    header->flags = 0;
    header->payload_length = 0;
    
    // Timestamp
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    header->timestamp = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static inline int message_validate(const message_t* msg) {
    if (!msg) return -1;
    if (msg->header.magic != PROTOCOL_MAGIC) return -2;
    if (msg->header.version != PROTOCOL_VERSION) return -3;
    if (msg->header.payload_length > MAX_PAYLOAD_SIZE) return -4;
    return 0;
}

static inline size_t message_total_size(const message_t* msg) {
    return sizeof(message_header_t) + msg->header.payload_length;
}

static inline const char* message_type_string(message_type_t type) {
    switch (type) {
        case MSG_CONNECT:    return "CONNECT";
        case MSG_DISCONNECT: return "DISCONNECT";
        case MSG_ACK:        return "ACK";
        case MSG_NACK:       return "NACK";
        case MSG_PING:       return "PING";
        case MSG_PONG:       return "PONG";
        default:             return "UNKNOWN";
    }
}

#endif // P2P_PROTOCOL_H