#ifndef P2P_NAT_TYPES_H
#define P2P_NAT_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "../../common/protocol.h"
#include "../../common/config.h"
#include "stun.h"

// ============================================
// NAT TYPES
// ============================================
typedef enum {
    NAT_TYPE_UNKNOWN = 0,
    NAT_TYPE_NONE,
    NAT_TYPE_FULL_CONE,
    NAT_TYPE_RESTRICTED_CONE,
    NAT_TYPE_PORT_RESTRICTED,
    NAT_TYPE_SYMMETRIC
} nat_type_t;

typedef enum {
    PUNCH_STATE_IDLE = 0,
    PUNCH_STATE_INITIATED,
    PUNCH_STATE_PUNCHING,
    PUNCH_STATE_CONNECTED,
    PUNCH_STATE_RELAY_FALLBACK,
    PUNCH_STATE_FAILED
} punch_state_t;

// ============================================
// NAT INFO
// ============================================
typedef struct {
    char local_ip[46];
    uint16_t local_port;
    char public_ip[46];
    uint16_t public_port;
    nat_type_t nat_type;
    bool discovered;
} nat_info_t;

// ============================================
// PUNCH CONTEXT (per-peer)
// ============================================
#define MAX_PUNCHES 16

typedef struct {
    char peer_id[MAX_ID_LENGTH];
    char peer_public_ip[46];
    uint16_t peer_public_port;
    char peer_local_ip[46];
    uint16_t peer_local_port;
    uint16_t peer_p2p_port;

    punch_state_t state;
    int attempts;
    int connected_fd;
    int udp_fd;
    bool is_initiator;

    uint64_t started_at;
    uint64_t connected_at;
} punch_context_t;

// ============================================
// NAT TRAVERSAL MANAGER
// ============================================
typedef struct {
    char relay_host[256];
    uint16_t relay_port;

    nat_info_t local_nat;

    stun_result_t stun_result;
    bool stun_discovered;

    punch_context_t punches[MAX_PUNCHES];
    int punch_count;

    int udp_punch_fd;

    pthread_mutex_t mutex;
} nat_manager_t;

// ============================================
// PROTOCOL PAYLOADS
// ============================================
typedef struct __attribute__((packed)) {
    char public_ip[46];
    uint16_t public_port;
    uint8_t nat_type;
} payload_nat_info_t;

typedef struct __attribute__((packed)) {
    char target_peer_id[MAX_ID_LENGTH];
    char local_ip[46];
    uint16_t local_port;
    uint16_t p2p_listen_port;
} payload_punch_request_t;

typedef struct __attribute__((packed)) {
    char peer_id[MAX_ID_LENGTH];
    char peer_public_ip[46];
    uint16_t peer_public_port;
    char peer_local_ip[46];
    uint16_t peer_local_port;
    uint16_t peer_p2p_port;
    uint8_t you_are_initiator;
} payload_punch_instruction_t;

typedef struct __attribute__((packed)) {
    char peer_id[MAX_ID_LENGTH];
    uint8_t success;
    uint8_t method;
} payload_punch_result_t;

typedef struct __attribute__((packed)) {
    char target_peer_id[MAX_ID_LENGTH];
    uint32_t data_length;
    uint8_t data[MAX_PAYLOAD_SIZE - MAX_ID_LENGTH - 4];
} payload_relay_proxy_t;

// ============================================
// STRING HELPERS
// ============================================
const char* nat_type_string(nat_type_t type);
const char* punch_state_string(punch_state_t state);

#endif // P2P_NAT_TYPES_H