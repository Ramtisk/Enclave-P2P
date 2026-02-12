#ifndef P2P_NAT_TRAVERSAL_H
#define P2P_NAT_TRAVERSAL_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <netinet/in.h>
#include "../../common/protocol.h"
#include "../../common/config.h"
#include "stun.h"

// ============================================
// NAT TYPES
// ============================================
typedef enum {
    NAT_TYPE_UNKNOWN = 0,
    NAT_TYPE_NONE,                  // Public IP, no NAT
    NAT_TYPE_FULL_CONE,             // Easy punch
    NAT_TYPE_RESTRICTED_CONE,       // Need simultaneous open
    NAT_TYPE_PORT_RESTRICTED,       // Need simultaneous open
    NAT_TYPE_SYMMETRIC              // Relay fallback required
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
// NAT INFO (discovered via STUN + relay)
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
    int connected_fd;           // TCP fd if punch succeeded
    int udp_fd;                 // UDP fd for hole punch probes
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
    
    // Our NAT info
    nat_info_t local_nat;
    
    // STUN discovery
    stun_result_t stun_result;
    bool stun_discovered;
    
    // Active punch attempts
    punch_context_t punches[MAX_PUNCHES];
    int punch_count;
    
    // UDP socket for hole punching
    int udp_punch_fd;
    
    pthread_mutex_t mutex;
} nat_manager_t;

// ============================================
// PROTOCOL PAYLOADS
// ============================================

// Relay → Client: your public endpoint
typedef struct __attribute__((packed)) {
    char public_ip[46];
    uint16_t public_port;
    uint8_t nat_type;
} payload_nat_info_t;

// Client → Relay: punch request
typedef struct __attribute__((packed)) {
    char target_peer_id[MAX_ID_LENGTH];
    char local_ip[46];
    uint16_t local_port;
    uint16_t p2p_listen_port;
} payload_punch_request_t;

// Relay → Both: punch instruction
typedef struct __attribute__((packed)) {
    char peer_id[MAX_ID_LENGTH];
    char peer_public_ip[46];
    uint16_t peer_public_port;
    char peer_local_ip[46];
    uint16_t peer_local_port;
    uint16_t peer_p2p_port;
    uint8_t you_are_initiator;
} payload_punch_instruction_t;

// Client → Relay: punch result
typedef struct __attribute__((packed)) {
    char peer_id[MAX_ID_LENGTH];
    uint8_t success;
    uint8_t method;     // 0=direct, 1=UDP punch, 2=relay
} payload_punch_result_t;

// Client → Relay → Client: proxied data (symmetric NAT fallback)
typedef struct __attribute__((packed)) {
    char target_peer_id[MAX_ID_LENGTH];
    uint32_t data_length;
    uint8_t data[MAX_PAYLOAD_SIZE - MAX_ID_LENGTH - 4];
} payload_relay_proxy_t;

// ============================================
// API
// ============================================

// Lifecycle
int  nat_manager_init(nat_manager_t* mgr, const char* relay_host, uint16_t relay_port);
void nat_manager_cleanup(nat_manager_t* mgr);

// Discovery — call after connecting to relay
int  nat_discover(nat_manager_t* mgr, int relay_socket_fd);
void nat_set_info(nat_manager_t* mgr, const payload_nat_info_t* info);

// STUN discovery (direct, no relay needed)
int  nat_stun_discover(nat_manager_t* mgr);

// Hole punching — returns connected socket fd or -1
int  nat_punch_to_peer(nat_manager_t* mgr, int relay_socket_fd,
                       const char* peer_id, const char* sender_id);

// Handle incoming punch instruction from relay
int  nat_handle_punch_instruction(nat_manager_t* mgr, 
                                   const payload_punch_instruction_t* instr);

// UDP hole punch (called by handle_punch_instruction)
int  nat_udp_hole_punch(nat_manager_t* mgr, punch_context_t* punch);

// Get connection to peer (may be direct or relay-proxied)
int  nat_get_peer_connection(nat_manager_t* mgr, const char* peer_id);

// Relay fallback for symmetric NAT
int  nat_relay_send(nat_manager_t* mgr, int relay_fd, 
                    const char* peer_id, const void* data, size_t len);

// Helpers
const char* nat_type_string(nat_type_t type);
const char* punch_state_string(punch_state_t state);
int  nat_try_connect(const char* ip, uint16_t port, uint16_t local_port, int timeout_ms);

#endif // P2P_NAT_TRAVERSAL_H