#ifndef P2P_RELAY_TYPES_H
#define P2P_RELAY_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include "../../common/config.h"
#include "../../common/protocol.h"
#include "../../core/group_mgmt/group_manager.h"

// ============================================
// CLIENT CONNECTION
// ============================================
typedef struct {
    int socket_fd;
    char id[MAX_ID_LENGTH];
    char ip[46];
    uint16_t port;
    uint64_t connected_at;
    uint64_t last_ping;
    bool authenticated;
    char group_id[MAX_ID_LENGTH];
} client_connection_t;

// ============================================
// RELAY SERVER
// ============================================
typedef struct {
    int server_fd;
    uint16_t port;
    bool running;

    client_connection_t clients[MAX_CLIENTS];
    int client_count;

    group_manager_t group_mgr;

    uint64_t total_messages;
    uint64_t total_bytes_sent;
    uint64_t total_bytes_received;
} relay_server_t;

#endif // P2P_RELAY_TYPES_H