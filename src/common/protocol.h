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
    MSG_GROUP_VOTE_REQ  = 0x25,
    MSG_GROUP_APPROVED  = 0x26,
    MSG_GROUP_REJECTED  = 0x27,
    MSG_GROUP_INFO      = 0x28,
    
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
    uint32_t magic;
    uint8_t  version;
    uint8_t  type;
    uint16_t flags;
    uint32_t payload_length;
    uint64_t timestamp;
    char     sender_id[MAX_ID_LENGTH];
    char     target_id[MAX_ID_LENGTH];
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
    uint16_t listen_port;
} payload_connect_t;

// MSG_PEER_LIST
typedef struct __attribute__((packed)) {
    uint32_t peer_count;
    struct {
        char id[MAX_ID_LENGTH];
        char ip[46];
        uint16_t port;
        uint8_t online;
    } peers[MAX_CLIENTS];
} payload_peer_list_t;

// ============================================
// GROUP PAYLOAD STRUCTURES (Phase 2)
// ============================================

#define MAX_GROUP_NAME 64
#define INVITE_TOKEN_LENGTH 32

// MSG_GROUP_CREATE
typedef struct __attribute__((packed)) {
    char group_name[MAX_GROUP_NAME];
} payload_group_create_t;

// MSG_GROUP_CREATE response (in ACK payload)
typedef struct __attribute__((packed)) {
    char group_id[MAX_ID_LENGTH];
    char invite_token[INVITE_TOKEN_LENGTH];
} payload_group_created_t;

// MSG_GROUP_JOIN (using invite token)
typedef struct __attribute__((packed)) {
    char invite_token[INVITE_TOKEN_LENGTH];
} payload_group_join_t;

// MSG_GROUP_VOTE_REQ (sent to existing members)
typedef struct __attribute__((packed)) {
    char group_id[MAX_ID_LENGTH];
    char requester_id[MAX_ID_LENGTH];
    char request_id[MAX_ID_LENGTH];  // Unique ID for this vote request
} payload_vote_request_t;

// MSG_GROUP_VOTE (member's response)
typedef struct __attribute__((packed)) {
    char group_id[MAX_ID_LENGTH];
    char request_id[MAX_ID_LENGTH];
    char requester_id[MAX_ID_LENGTH];
    uint8_t approved;  // 1 = yes, 0 = no
} payload_group_vote_t;

// MSG_GROUP_LEAVE
typedef struct __attribute__((packed)) {
    char group_id[MAX_ID_LENGTH];
} payload_group_leave_t;

// MSG_GROUP_APPROVED / MSG_GROUP_REJECTED
typedef struct __attribute__((packed)) {
    char group_id[MAX_ID_LENGTH];
    char group_name[MAX_GROUP_NAME];
    uint32_t member_count;
} payload_group_result_t;

// MSG_GROUP_INFO (peer list for approved member)
typedef struct __attribute__((packed)) {
    char group_id[MAX_ID_LENGTH];
    uint32_t peer_count;
    struct {
        char id[MAX_ID_LENGTH];
        char ip[46];
        uint16_t port;
    } peers[MAX_GROUP_MEMBERS];
} payload_group_info_t;

// MSG_GROUP_INVITE (generate new invite token)
typedef struct __attribute__((packed)) {
    char group_id[MAX_ID_LENGTH];
} payload_invite_request_t;

// Response to MSG_GROUP_INVITE
typedef struct __attribute__((packed)) {
    char group_id[MAX_ID_LENGTH];
    char invite_token[INVITE_TOKEN_LENGTH];
} payload_invite_response_t;

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
        case MSG_CONNECT:       return "CONNECT";
        case MSG_DISCONNECT:    return "DISCONNECT";
        case MSG_ACK:           return "ACK";
        case MSG_NACK:          return "NACK";
        case MSG_PING:          return "PING";
        case MSG_PONG:          return "PONG";
        case MSG_GROUP_CREATE:  return "GROUP_CREATE";
        case MSG_GROUP_JOIN:    return "GROUP_JOIN";
        case MSG_GROUP_LEAVE:   return "GROUP_LEAVE";
        case MSG_GROUP_VOTE:    return "GROUP_VOTE";
        case MSG_GROUP_INVITE:  return "GROUP_INVITE";
        case MSG_GROUP_VOTE_REQ: return "GROUP_VOTE_REQ";
        case MSG_GROUP_APPROVED: return "GROUP_APPROVED";
        case MSG_GROUP_REJECTED: return "GROUP_REJECTED";
        case MSG_GROUP_INFO:    return "GROUP_INFO";
        case MSG_PEER_LIST:     return "PEER_LIST";
        default:                return "UNKNOWN";
    }
}

#endif // P2P_PROTOCOL_H