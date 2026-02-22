#ifndef P2P_CLIENT_TYPES_H
#define P2P_CLIENT_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "../../common/protocol.h"
#include "../../common/config.h"
#include "../../transfer/p2p_transfer.h"
#include "../nat_traversal/nat_traversal.h"

// ============================================
// CALLBACK TYPES
// ============================================
typedef void (*message_callback_t)(message_t* msg, void* user_data);

// ============================================
// CLIENT STRUCTURE
// ============================================
typedef struct {
    // Identity
    char id[MAX_ID_LENGTH];

    // Connection
    int socket_fd;
    char relay_host[256];
    uint16_t relay_port;
    bool connected;

    // Threading
    pthread_t recv_thread;
    bool recv_thread_running;
    pthread_t ping_thread;
    bool ping_thread_running;
    pthread_mutex_t send_mutex;

    // Callbacks
    message_callback_t on_message;
    void* callback_user_data;

    // Ping/Pong
    uint32_t ping_counter;
    uint64_t last_ping_sent;
    uint64_t rtt_ms;

    // Group info
    char group_id[MAX_ID_LENGTH];
    char group_name[MAX_GROUP_NAME];
    char invite_token[INVITE_TOKEN_LENGTH];
    bool in_group;

    // Pending vote request
    char pending_vote_request_id[MAX_ID_LENGTH];
    char pending_vote_requester[MAX_ID_LENGTH];
    char pending_vote_group[MAX_ID_LENGTH];
    bool has_pending_vote;

    // File transfer
    file_manager_t file_mgr;
    p2p_server_t p2p_server;
    uint16_t p2p_listen_port;

    // NAT Traversal
    nat_manager_t nat_mgr;

    // Statistics
    uint64_t messages_sent;
    uint64_t messages_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
} p2p_client_t;

#endif // P2P_CLIENT_TYPES_H