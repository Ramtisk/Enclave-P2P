#ifndef P2P_RELAY_H
#define P2P_RELAY_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "../common/config.h"
#include "../common/protocol.h"
#include "../core/group_mgmt.h"

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
    char group_id[MAX_ID_LENGTH];  // Current group (Phase 2)
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
    
    // Group management (Phase 2)
    group_manager_t group_mgr;
    
    // Statistics
    uint64_t total_messages;
    uint64_t total_bytes_sent;
    uint64_t total_bytes_received;
} relay_server_t;

// ============================================
// FUNCTIONS
// ============================================

// Lifecycle
int  relay_init(relay_server_t* server, uint16_t port);
int  relay_start(relay_server_t* server);
void relay_stop(relay_server_t* server);
void relay_cleanup(relay_server_t* server);

// Client management
int  relay_accept_client(relay_server_t* server);
void relay_disconnect_client(relay_server_t* server, int client_index);
client_connection_t* relay_find_client_by_id(relay_server_t* server, const char* id);
int  relay_find_client_index_by_id(relay_server_t* server, const char* id);

// Message handling
int relay_process_message(relay_server_t* server, int client_index, message_t* msg);
int relay_send_to_client(relay_server_t* server, int client_index, message_t* msg);
int relay_broadcast(relay_server_t* server, message_t* msg, int exclude_index);

// Basic message handlers
int relay_handle_ping(relay_server_t* server, int client_index, message_t* msg);
int relay_handle_connect(relay_server_t* server, int client_index, message_t* msg);
int relay_handle_disconnect(relay_server_t* server, int client_index, message_t* msg);

// Group message handlers (Phase 2)
int relay_handle_group_create(relay_server_t* server, int client_index, message_t* msg);
int relay_handle_group_join(relay_server_t* server, int client_index, message_t* msg);
int relay_handle_group_vote(relay_server_t* server, int client_index, message_t* msg);
int relay_handle_group_leave(relay_server_t* server, int client_index, message_t* msg);
int relay_handle_group_invite(relay_server_t* server, int client_index, message_t* msg);

// Group utilities
int relay_send_vote_request_to_members(relay_server_t* server, group_t* group, 
                                       pending_join_t* pending);
int relay_send_group_info(relay_server_t* server, int client_index, group_t* group);

#endif // P2P_RELAY_H