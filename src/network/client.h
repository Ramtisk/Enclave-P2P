#ifndef P2P_CLIENT_H
#define P2P_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "../common/config.h"
#include "../common/protocol.h"

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
    pthread_t ping_thread;          // NEW: Auto-ping thread
    bool ping_thread_running;       // NEW: Ping thread control
    pthread_mutex_t send_mutex;
    
    // Callbacks
    message_callback_t on_message;
    void* callback_user_data;
    
    // Ping/Pong
    uint32_t ping_counter;
    uint64_t last_ping_sent;
    uint64_t rtt_ms;
    
    // Statistics
    uint64_t messages_sent;
    uint64_t messages_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
} p2p_client_t;

// ============================================
// FUNCTIONS
// ============================================

// Lifecycle
int  client_init(p2p_client_t* client, const char* relay_host, uint16_t relay_port);
int  client_connect(p2p_client_t* client);
void client_disconnect(p2p_client_t* client);
void client_cleanup(p2p_client_t* client);

// State
bool client_is_connected(p2p_client_t* client);

// Messaging
int client_send_message(p2p_client_t* client, message_t* msg);
int client_send_ping(p2p_client_t* client);

// Callbacks
void client_set_message_callback(p2p_client_t* client, message_callback_t callback, void* user_data);

#endif // P2P_CLIENT_H