#include "client.h"
#include "../common/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

// ============================================
// HELPER FUNCTIONS
// ============================================

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void generate_client_id(char* id, size_t len) {
    snprintf(id, len, "peer_%d_%lu", getpid(), get_timestamp_ms() % 100000);
}

// ============================================
// RECEIVE THREAD
// ============================================

static void* client_recv_thread(void* arg) {
    p2p_client_t* client = (p2p_client_t*)arg;
    uint8_t buffer[READ_BUFFER_SIZE];
    
    LOG_DEBUG("Receive thread started");
    
    while (client->recv_thread_running && client->connected) {
        ssize_t bytes = recv(client->socket_fd, buffer, sizeof(buffer), 0);
        
        if (bytes <= 0) {
            if (bytes == 0) {
                LOG_INFO("Connection closed by relay");
            } else if (errno != EINTR) {
                LOG_ERROR("Receive error: %s", strerror(errno));
            }
            client->connected = false;
            break;
        }
        
        client->bytes_received += bytes;
        
        if (bytes >= (ssize_t)sizeof(message_header_t)) {
            message_t* msg = (message_t*)buffer;
            
            int validation = message_validate(msg);
            if (validation != 0) {
                LOG_WARN("Invalid message received (error: %d)", validation);
                continue;
            }
            
            client->messages_received++;
            
            LOG_DEBUG("Received %s from %s", 
                     message_type_string(msg->header.type),
                     msg->header.sender_id);
            
            // Handle PONG internally
            if (msg->header.type == MSG_PONG) {
                payload_ping_t* pong = (payload_ping_t*)msg->payload;
                uint64_t now = get_timestamp_ms();
                client->rtt_ms = now - pong->ping_time;
                LOG_DEBUG("PONG received (id: %u, RTT: %lu ms)", 
                         pong->ping_id, client->rtt_ms);
            }
            
            // Handle vote request internally
            if (msg->header.type == MSG_GROUP_VOTE_REQ) {
                payload_vote_request_t* vote_req = (payload_vote_request_t*)msg->payload;
                strncpy(client->pending_vote_request_id, vote_req->request_id, 
                       MAX_ID_LENGTH - 1);
                strncpy(client->pending_vote_requester, vote_req->requester_id,
                       MAX_ID_LENGTH - 1);
                strncpy(client->pending_vote_group, vote_req->group_id,
                       MAX_ID_LENGTH - 1);
                client->has_pending_vote = true;
                
                LOG_INFO("=== VOTE REQUEST ===");
                LOG_INFO("User '%s' wants to join your group.", vote_req->requester_id);
                LOG_INFO("Press 'y' to approve or 'n' to reject");
            }
            
            // Handle group approval
            if (msg->header.type == MSG_GROUP_APPROVED) {
                payload_group_result_t* result = (payload_group_result_t*)msg->payload;
                strncpy(client->group_id, result->group_id, MAX_ID_LENGTH - 1);
                strncpy(client->group_name, result->group_name, MAX_GROUP_NAME - 1);
                client->in_group = true;
                
                LOG_INFO("=== JOINED GROUP ===");
                LOG_INFO("Group: %s (%s)", result->group_name, result->group_id);
                LOG_INFO("Members: %u", result->member_count);
            }
            
            // Handle group rejection
            if (msg->header.type == MSG_GROUP_REJECTED) {
                LOG_WARN("=== JOIN REJECTED ===");
                LOG_WARN("Your request to join the group was rejected.");
            }
            
            // Handle group info
            if (msg->header.type == MSG_GROUP_INFO) {
                payload_group_info_t* info = (payload_group_info_t*)msg->payload;
                LOG_INFO("=== GROUP PEERS ===");
                for (uint32_t i = 0; i < info->peer_count; i++) {
                    LOG_INFO("  - %s (%s:%d)", 
                            info->peers[i].id, info->peers[i].ip, info->peers[i].port);
                }
            }
            
            if (client->on_message) {
                client->on_message(msg, client->callback_user_data);
            }
        }
    }
    
    LOG_DEBUG("Receive thread exiting");
    return NULL;
}

// ============================================
// PING THREAD (AUTO PING)
// ============================================

static void* client_ping_thread(void* arg) {
    p2p_client_t* client = (p2p_client_t*)arg;
    
    LOG_DEBUG("Auto-ping thread started (interval: %d ms)", PING_INTERVAL_MS);
    
    while (client->ping_thread_running && client->connected) {
        usleep(PING_INTERVAL_MS * 1000);
        
        if (!client->connected || !client->ping_thread_running) {
            break;
        }
        
        if (client_send_ping(client) == 0) {
            LOG_TRACE("Auto-ping sent (id: %u)", client->ping_counter);
        }
    }
    
    LOG_DEBUG("Auto-ping thread exiting");
    return NULL;
}

// ============================================
// INITIALIZATION
// ============================================

int client_init(p2p_client_t* client, const char* relay_host, uint16_t relay_port) {
    memset(client, 0, sizeof(p2p_client_t));
    
    generate_client_id(client->id, sizeof(client->id));
    strncpy(client->relay_host, relay_host, sizeof(client->relay_host) - 1);
    client->relay_port = relay_port;
    client->socket_fd = -1;
    client->connected = false;
    client->in_group = false;
    client->has_pending_vote = false;
    
    pthread_mutex_init(&client->send_mutex, NULL);
    
    LOG_INFO("Client initialized: %s", client->id);
    return 0;
}

// ============================================
// CONNECTION
// ============================================

int client_connect(p2p_client_t* client) {
    LOG_INFO("Connecting to relay %s:%d...", client->relay_host, client->relay_port);
    
    client->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client->socket_fd < 0) {
        LOG_ERROR("Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    struct hostent* host = gethostbyname(client->relay_host);
    if (!host) {
        LOG_ERROR("Failed to resolve host: %s", client->relay_host);
        close(client->socket_fd);
        client->socket_fd = -1;
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(client->relay_port);
    memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);
    
    if (connect(client->socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("Failed to connect: %s", strerror(errno));
        close(client->socket_fd);
        client->socket_fd = -1;
        return -1;
    }
    
    client->connected = true;
    LOG_INFO("Connected to relay!");
    
    // Start receive thread
    client->recv_thread_running = true;
    if (pthread_create(&client->recv_thread, NULL, client_recv_thread, client) != 0) {
        LOG_ERROR("Failed to create receive thread");
        close(client->socket_fd);
        client->socket_fd = -1;
        client->connected = false;
        return -1;
    }
    
    // Start auto-ping thread
    client->ping_thread_running = true;
    if (pthread_create(&client->ping_thread, NULL, client_ping_thread, client) != 0) {
        LOG_ERROR("Failed to create ping thread");
        client->recv_thread_running = false;
        pthread_join(client->recv_thread, NULL);
        close(client->socket_fd);
        client->socket_fd = -1;
        client->connected = false;
        return -1;
    }
    
    // Send CONNECT message
    message_t connect_msg;
    memset(&connect_msg, 0, sizeof(connect_msg));
    message_header_init(&connect_msg.header, MSG_CONNECT);
    strncpy(connect_msg.header.sender_id, client->id, MAX_ID_LENGTH - 1);
    
    payload_connect_t* payload = (payload_connect_t*)connect_msg.payload;
    strncpy(payload->client_id, client->id, MAX_ID_LENGTH - 1);
    snprintf(payload->client_version, sizeof(payload->client_version), 
             "%d.%d.%d", P2P_VERSION_MAJOR, P2P_VERSION_MINOR, P2P_VERSION_PATCH);
    payload->listen_port = 0;
    
    connect_msg.header.payload_length = sizeof(payload_connect_t);
    
    if (client_send_message(client, &connect_msg) != 0) {
        LOG_ERROR("Failed to send CONNECT message");
        client_disconnect(client);
        return -1;
    }
    
    LOG_INFO("CONNECT message sent");
    return 0;
}

void client_disconnect(p2p_client_t* client) {
    if (!client->connected) return;
    
    LOG_INFO("Disconnecting from relay...");
    
    // Leave group if in one
    if (client->in_group) {
        client_leave_group(client);
    }
    
    // Send DISCONNECT message
    message_t disconnect_msg;
    memset(&disconnect_msg, 0, sizeof(disconnect_msg));
    message_header_init(&disconnect_msg.header, MSG_DISCONNECT);
    strncpy(disconnect_msg.header.sender_id, client->id, MAX_ID_LENGTH - 1);
    client_send_message(client, &disconnect_msg);
    
    // Stop threads
    client->recv_thread_running = false;
    client->ping_thread_running = false;
    client->connected = false;
    
    if (client->socket_fd > 0) {
        shutdown(client->socket_fd, SHUT_RDWR);
        close(client->socket_fd);
        client->socket_fd = -1;
    }
    
    pthread_join(client->recv_thread, NULL);
    pthread_join(client->ping_thread, NULL);
    
    LOG_INFO("Disconnected");
}

void client_cleanup(p2p_client_t* client) {
    if (client->connected) {
        client_disconnect(client);
    }
    pthread_mutex_destroy(&client->send_mutex);
    
    LOG_INFO("Client cleanup complete");
    LOG_INFO("Statistics: %lu msgs sent, %lu msgs received, %lu bytes sent, %lu bytes received",
             client->messages_sent, client->messages_received,
             client->bytes_sent, client->bytes_received);
}

// ============================================
// STATE
// ============================================

bool client_is_connected(p2p_client_t* client) {
    return client->connected;
}

// ============================================
// MESSAGING
// ============================================

int client_send_message(p2p_client_t* client, message_t* msg) {
    if (!client->connected) {
        LOG_WARN("Cannot send message: not connected");
        return -1;
    }
    
    pthread_mutex_lock(&client->send_mutex);
    
    size_t total_size = message_total_size(msg);
    ssize_t sent = send(client->socket_fd, msg, total_size, 0);
    
    pthread_mutex_unlock(&client->send_mutex);
    
    if (sent < 0) {
        LOG_ERROR("Send failed: %s", strerror(errno));
        return -1;
    }
    
    client->bytes_sent += sent;
    client->messages_sent++;
    
    LOG_TRACE("Sent %zd bytes (%s)", sent, message_type_string(msg->header.type));
    return 0;
}

int client_send_ping(p2p_client_t* client) {
    message_t ping;
    memset(&ping, 0, sizeof(ping));
    message_header_init(&ping.header, MSG_PING);
    strncpy(ping.header.sender_id, client->id, MAX_ID_LENGTH - 1);
    
    payload_ping_t* payload = (payload_ping_t*)ping.payload;
    payload->ping_time = get_timestamp_ms();
    payload->ping_id = ++client->ping_counter;
    ping.header.payload_length = sizeof(payload_ping_t);
    
    client->last_ping_sent = payload->ping_time;
    
    LOG_DEBUG("Sending PING (id: %u)", payload->ping_id);
    return client_send_message(client, &ping);
}

// ============================================
// GROUP OPERATIONS (Phase 2)
// ============================================

int client_create_group(p2p_client_t* client, const char* group_name) {
    if (client->in_group) {
        LOG_WARN("Already in a group. Leave first.");
        return -1;
    }
    
    LOG_INFO("Creating group: %s", group_name);
    
    message_t msg;
    memset(&msg, 0, sizeof(msg));
    message_header_init(&msg.header, MSG_GROUP_CREATE);
    strncpy(msg.header.sender_id, client->id, MAX_ID_LENGTH - 1);
    
    payload_group_create_t* payload = (payload_group_create_t*)msg.payload;
    strncpy(payload->group_name, group_name, MAX_GROUP_NAME - 1);
    msg.header.payload_length = sizeof(payload_group_create_t);
    
    return client_send_message(client, &msg);
}

int client_join_group(p2p_client_t* client, const char* invite_token) {
    if (client->in_group) {
        LOG_WARN("Already in a group. Leave first.");
        return -1;
    }
    
    LOG_INFO("Joining group with token: %s", invite_token);
    
    message_t msg;
    memset(&msg, 0, sizeof(msg));
    message_header_init(&msg.header, MSG_GROUP_JOIN);
    strncpy(msg.header.sender_id, client->id, MAX_ID_LENGTH - 1);
    
    payload_group_join_t* payload = (payload_group_join_t*)msg.payload;
    strncpy(payload->invite_token, invite_token, INVITE_TOKEN_LENGTH - 1);
    msg.header.payload_length = sizeof(payload_group_join_t);
    
    return client_send_message(client, &msg);
}

int client_leave_group(p2p_client_t* client) {
    if (!client->in_group) {
        LOG_WARN("Not in a group.");
        return -1;
    }
    
    LOG_INFO("Leaving group: %s", client->group_id);
    
    message_t msg;
    memset(&msg, 0, sizeof(msg));
    message_header_init(&msg.header, MSG_GROUP_LEAVE);
    strncpy(msg.header.sender_id, client->id, MAX_ID_LENGTH - 1);
    
    payload_group_leave_t* payload = (payload_group_leave_t*)msg.payload;
    strncpy(payload->group_id, client->group_id, MAX_ID_LENGTH - 1);
    msg.header.payload_length = sizeof(payload_group_leave_t);
    
    int result = client_send_message(client, &msg);
    
    // Clear local state
    memset(client->group_id, 0, sizeof(client->group_id));
    memset(client->group_name, 0, sizeof(client->group_name));
    memset(client->invite_token, 0, sizeof(client->invite_token));
    client->in_group = false;
    
    return result;
}

int client_vote(p2p_client_t* client, bool approve) {
    if (!client->has_pending_vote) {
        LOG_WARN("No pending vote request.");
        return -1;
    }
    
    LOG_INFO("Voting %s for %s", approve ? "YES" : "NO", client->pending_vote_requester);
    
    message_t msg;
    memset(&msg, 0, sizeof(msg));
    message_header_init(&msg.header, MSG_GROUP_VOTE);
    strncpy(msg.header.sender_id, client->id, MAX_ID_LENGTH - 1);
    
    payload_group_vote_t* payload = (payload_group_vote_t*)msg.payload;
    strncpy(payload->group_id, client->pending_vote_group, MAX_ID_LENGTH - 1);
    strncpy(payload->request_id, client->pending_vote_request_id, MAX_ID_LENGTH - 1);
    strncpy(payload->requester_id, client->pending_vote_requester, MAX_ID_LENGTH - 1);
    payload->approved = approve ? 1 : 0;
    msg.header.payload_length = sizeof(payload_group_vote_t);
    
    // Clear pending vote
    client->has_pending_vote = false;
    memset(client->pending_vote_request_id, 0, sizeof(client->pending_vote_request_id));
    memset(client->pending_vote_requester, 0, sizeof(client->pending_vote_requester));
    memset(client->pending_vote_group, 0, sizeof(client->pending_vote_group));
    
    return client_send_message(client, &msg);
}

int client_request_invite(p2p_client_t* client) {
    if (!client->in_group) {
        LOG_WARN("Not in a group.");
        return -1;
    }
    
    LOG_INFO("Requesting new invite token");
    
    message_t msg;
    memset(&msg, 0, sizeof(msg));
    message_header_init(&msg.header, MSG_GROUP_INVITE);
    strncpy(msg.header.sender_id, client->id, MAX_ID_LENGTH - 1);
    
    payload_invite_request_t* payload = (payload_invite_request_t*)msg.payload;
    strncpy(payload->group_id, client->group_id, MAX_ID_LENGTH - 1);
    msg.header.payload_length = sizeof(payload_invite_request_t);
    
    return client_send_message(client, &msg);
}

// ============================================
// CALLBACKS
// ============================================

void client_set_message_callback(p2p_client_t* client, message_callback_t callback, void* user_data) {
    client->on_message = callback;
    client->callback_user_data = user_data;
}