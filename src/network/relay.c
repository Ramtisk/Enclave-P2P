#include "relay.h"
#include "../common/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

// ============================================
// HELPER FUNCTIONS
// ============================================

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void generate_client_id(char* id, size_t len) {
    static int counter = 0;
    snprintf(id, len, "client_%d_%lu", ++counter, get_timestamp_ms() % 10000);
}

// ============================================
// INITIALIZATION
// ============================================

int relay_init(relay_server_t* server, uint16_t port) {
    memset(server, 0, sizeof(relay_server_t));
    server->port = port;
    server->running = false;
    server->client_count = 0;
    
    // Initialize client array
    for (int i = 0; i < MAX_CLIENTS; i++) {
        server->clients[i].socket_fd = -1;
    }
    
    // Initialize group manager (Phase 2)
    group_manager_init(&server->group_mgr);
    
    // Create socket
    server->server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->server_fd < 0) {
        LOG_ERROR("Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    // SO_REUSEADDR option
    int opt = 1;
    if (setsockopt(server->server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        LOG_WARN("Failed to set SO_REUSEADDR: %s", strerror(errno));
    }
    
    // Bind
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(server->server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("Failed to bind to port %d: %s", port, strerror(errno));
        close(server->server_fd);
        return -1;
    }
    
    // Listen
    if (listen(server->server_fd, 10) < 0) {
        LOG_ERROR("Failed to listen: %s", strerror(errno));
        close(server->server_fd);
        return -1;
    }
    
    // Non-blocking
    if (set_nonblocking(server->server_fd) < 0) {
        LOG_WARN("Failed to set non-blocking on server socket");
    }
    
    LOG_INFO("Relay initialized on port %d", port);
    return 0;
}

// ============================================
// MAIN LOOP
// ============================================

int relay_start(relay_server_t* server) {
    server->running = true;
    LOG_INFO("Relay starting main loop...");
    
    fd_set read_fds;
    struct timeval timeout;
    
    while (server->running) {
        FD_ZERO(&read_fds);
        FD_SET(server->server_fd, &read_fds);
        int max_fd = server->server_fd;
        
        // Add clients to fd_set
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (server->clients[i].socket_fd > 0) {
                FD_SET(server->clients[i].socket_fd, &read_fds);
                if (server->clients[i].socket_fd > max_fd) {
                    max_fd = server->clients[i].socket_fd;
                }
            }
        }
        
        // Timeout for ping checks
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (activity < 0 && errno != EINTR) {
            LOG_ERROR("Select error: %s", strerror(errno));
            continue;
        }
        
        // New connection?
        if (FD_ISSET(server->server_fd, &read_fds)) {
            relay_accept_client(server);
        }
        
        // Data from clients?
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (server->clients[i].socket_fd > 0 && 
                FD_ISSET(server->clients[i].socket_fd, &read_fds)) {
                
                uint8_t buffer[READ_BUFFER_SIZE];
                ssize_t bytes = recv(server->clients[i].socket_fd, buffer, 
                                    sizeof(buffer), 0);
                
                if (bytes <= 0) {
                    if (bytes == 0) {
                        LOG_INFO("Client %s disconnected", server->clients[i].id);
                    } else {
                        LOG_ERROR("Error reading from client %s: %s", 
                                 server->clients[i].id, strerror(errno));
                    }
                    relay_disconnect_client(server, i);
                } else {
                    server->total_bytes_received += bytes;
                    
                    LOG_DEBUG("Received %zd bytes from client %s", 
                             bytes, server->clients[i].id);
                    
                    if (bytes >= (ssize_t)sizeof(message_header_t)) {
                        message_t* msg = (message_t*)buffer;
                        
                        int validation = message_validate(msg);
                        if (validation == 0) {
                            relay_process_message(server, i, msg);
                            server->total_messages++;
                        } else {
                            LOG_WARN("Invalid message from %s (error: %d)", 
                                    server->clients[i].id, validation);
                        }
                    }
                }
            }
        }
        
        // Check timeouts
        uint64_t now = get_timestamp_ms();
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (server->clients[i].socket_fd > 0) {
                uint64_t diff = now - server->clients[i].last_ping;
                if (diff > CONNECTION_TIMEOUT_MS) {
                    LOG_WARN("Client %s timeout (no ping for %lu ms)",
                            server->clients[i].id, diff);
                    relay_disconnect_client(server, i);
                }
            }
        }
    }
    
    return 0;
}

void relay_stop(relay_server_t* server) {
    LOG_INFO("Stopping relay...");
    server->running = false;
}

void relay_cleanup(relay_server_t* server) {
    // Disconnect all clients
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (server->clients[i].socket_fd > 0) {
            relay_disconnect_client(server, i);
        }
    }
    
    // Cleanup group manager
    group_manager_cleanup(&server->group_mgr);
    
    // Close server socket
    if (server->server_fd > 0) {
        close(server->server_fd);
        server->server_fd = -1;
    }
    
    LOG_INFO("Relay cleanup complete");
    LOG_INFO("Statistics: %lu messages, %lu bytes sent, %lu bytes received",
             server->total_messages, server->total_bytes_sent, 
             server->total_bytes_received);
}

// ============================================
// CLIENT MANAGEMENT
// ============================================

int relay_accept_client(relay_server_t* server) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    int client_fd = accept(server->server_fd, 
                          (struct sockaddr*)&client_addr, &addr_len);
    
    if (client_fd < 0) {
        if (errno != EWOULDBLOCK && errno != EAGAIN) {
            LOG_ERROR("Error accepting connection: %s", strerror(errno));
        }
        return -1;
    }
    
    // Find free slot
    int slot = -1;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (server->clients[i].socket_fd <= 0) {
            slot = i;
            break;
        }
    }
    
    if (slot < 0) {
        LOG_WARN("Server full, rejecting connection");
        close(client_fd);
        return -1;
    }
    
    set_nonblocking(client_fd);
    
    client_connection_t* client = &server->clients[slot];
    memset(client, 0, sizeof(client_connection_t));
    client->socket_fd = client_fd;
    client->port = ntohs(client_addr.sin_port);
    client->connected_at = get_timestamp_ms();
    client->last_ping = client->connected_at;
    client->authenticated = false;
    
    inet_ntop(AF_INET, &client_addr.sin_addr, client->ip, sizeof(client->ip));
    generate_client_id(client->id, sizeof(client->id));
    
    server->client_count++;
    
    LOG_INFO("New client connected: %s (%s:%d) [slot %d] [total: %d]",
            client->id, client->ip, client->port, slot, server->client_count);
    
    return slot;
}

void relay_disconnect_client(relay_server_t* server, int client_index) {
    if (client_index < 0 || client_index >= MAX_CLIENTS) return;
    
    client_connection_t* client = &server->clients[client_index];
    if (client->socket_fd <= 0) return;
    
    LOG_INFO("Disconnecting client %s", client->id);
    
    // Remove from any groups
    if (strlen(client->group_id) > 0) {
        group_t* group = group_find_by_id(&server->group_mgr, client->group_id);
        if (group) {
            group_remove_member(group, client->id);
            
            // If group is empty, destroy it
            if (group->member_count == 0) {
                LOG_INFO("Group %s is empty, destroying", group->group_id);
                group_destroy(&server->group_mgr, group->group_id);
            }
        }
    }
    
    close(client->socket_fd);
    client->socket_fd = -1;
    server->client_count--;
    
    LOG_INFO("Active clients: %d", server->client_count);
}

client_connection_t* relay_find_client_by_id(relay_server_t* server, const char* id) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (server->clients[i].socket_fd > 0 &&
            strcmp(server->clients[i].id, id) == 0) {
            return &server->clients[i];
        }
    }
    return NULL;
}

int relay_find_client_index_by_id(relay_server_t* server, const char* id) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (server->clients[i].socket_fd > 0 &&
            strcmp(server->clients[i].id, id) == 0) {
            return i;
        }
    }
    return -1;
}

// ============================================
// MESSAGE PROCESSING
// ============================================

int relay_process_message(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];
    
    LOG_DEBUG("Message type %s from client %s", 
              message_type_string(msg->header.type), client->id);
    
    switch (msg->header.type) {
        case MSG_PING:
            return relay_handle_ping(server, client_index, msg);
            
        case MSG_CONNECT:
            return relay_handle_connect(server, client_index, msg);
            
        case MSG_DISCONNECT:
            return relay_handle_disconnect(server, client_index, msg);
        
        // Group handlers (Phase 2)
        case MSG_GROUP_CREATE:
            return relay_handle_group_create(server, client_index, msg);
            
        case MSG_GROUP_JOIN:
            return relay_handle_group_join(server, client_index, msg);
            
        case MSG_GROUP_VOTE:
            return relay_handle_group_vote(server, client_index, msg);
            
        case MSG_GROUP_LEAVE:
            return relay_handle_group_leave(server, client_index, msg);
            
        case MSG_GROUP_INVITE:
            return relay_handle_group_invite(server, client_index, msg);
            
        default:
            LOG_WARN("Unknown message type: %d", msg->header.type);
            return -1;
    }
}

int relay_send_to_client(relay_server_t* server, int client_index, message_t* msg) {
    if (client_index < 0 || client_index >= MAX_CLIENTS) return -1;
    
    client_connection_t* client = &server->clients[client_index];
    if (client->socket_fd <= 0) return -1;
    
    size_t total_size = message_total_size(msg);
    ssize_t sent = send(client->socket_fd, msg, total_size, 0);
    
    if (sent < 0) {
        LOG_ERROR("Error sending to client %s: %s", client->id, strerror(errno));
        return -1;
    }
    
    server->total_bytes_sent += sent;
    LOG_TRACE("Sent %zd bytes to %s", sent, client->id);
    return 0;
}

int relay_broadcast(relay_server_t* server, message_t* msg, int exclude_index) {
    int count = 0;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (i != exclude_index && server->clients[i].socket_fd > 0) {
            if (relay_send_to_client(server, i, msg) == 0) {
                count++;
            }
        }
    }
    LOG_DEBUG("Broadcast to %d clients", count);
    return count;
}

// ============================================
// BASIC HANDLERS
// ============================================

int relay_handle_ping(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];
    
    client->last_ping = get_timestamp_ms();
    
    message_t pong;
    memset(&pong, 0, sizeof(pong));
    message_header_init(&pong.header, MSG_PONG);
    strncpy(pong.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(pong.header.target_id, client->id, MAX_ID_LENGTH - 1);
    
    payload_ping_t* ping_payload = (payload_ping_t*)msg->payload;
    payload_ping_t* pong_payload = (payload_ping_t*)pong.payload;
    pong_payload->ping_time = ping_payload->ping_time;
    pong_payload->ping_id = ping_payload->ping_id;
    pong.header.payload_length = sizeof(payload_ping_t);
    
    LOG_DEBUG("PING received from %s (id: %u), sending PONG", 
              client->id, ping_payload->ping_id);
    
    return relay_send_to_client(server, client_index, &pong);
}

int relay_handle_connect(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];
    payload_connect_t* payload = (payload_connect_t*)msg->payload;
    
    if (strlen(payload->client_id) > 0) {
        strncpy(client->id, payload->client_id, MAX_ID_LENGTH - 1);
    }
    
    client->authenticated = true;
    client->last_ping = get_timestamp_ms();
    
    LOG_INFO("Client %s authenticated (version: %s, listen_port: %d)", 
             client->id, payload->client_version, payload->listen_port);
    
    message_t ack;
    memset(&ack, 0, sizeof(ack));
    message_header_init(&ack.header, MSG_ACK);
    strncpy(ack.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(ack.header.target_id, client->id, MAX_ID_LENGTH - 1);
    
    return relay_send_to_client(server, client_index, &ack);
}

int relay_handle_disconnect(relay_server_t* server, int client_index, message_t* msg) {
    (void)msg;
    relay_disconnect_client(server, client_index);
    return 0;
}

// ============================================
// GROUP HANDLERS (Phase 2)
// ============================================

int relay_handle_group_create(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];
    payload_group_create_t* payload = (payload_group_create_t*)msg->payload;
    
    LOG_INFO("Client %s creating group: %s", client->id, payload->group_name);
    
    // Create the group
    group_t* group = group_create(&server->group_mgr, payload->group_name,
                                  client->id, client->ip, client->port);
    
    if (!group) {
        // Send NACK
        message_t nack;
        memset(&nack, 0, sizeof(nack));
        message_header_init(&nack.header, MSG_NACK);
        strncpy(nack.header.sender_id, "relay", MAX_ID_LENGTH - 1);
        strncpy(nack.header.target_id, client->id, MAX_ID_LENGTH - 1);
        return relay_send_to_client(server, client_index, &nack);
    }
    
    // Update client's group
    strncpy(client->group_id, group->group_id, MAX_ID_LENGTH - 1);
    
    // Send ACK with group info
    message_t ack;
    memset(&ack, 0, sizeof(ack));
    message_header_init(&ack.header, MSG_ACK);
    strncpy(ack.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(ack.header.target_id, client->id, MAX_ID_LENGTH - 1);
    
    payload_group_created_t* response = (payload_group_created_t*)ack.payload;
    strncpy(response->group_id, group->group_id, MAX_ID_LENGTH - 1);
    strncpy(response->invite_token, group->invite_token, INVITE_TOKEN_LENGTH - 1);
    ack.header.payload_length = sizeof(payload_group_created_t);
    
    LOG_INFO("Group created successfully: %s (token: %s)", 
             group->group_id, group->invite_token);
    
    return relay_send_to_client(server, client_index, &ack);
}

int relay_handle_group_join(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];
    payload_group_join_t* payload = (payload_group_join_t*)msg->payload;
    
    LOG_INFO("Client %s attempting to join with token: %s", 
             client->id, payload->invite_token);
    
    // Find group by token
    group_t* group = group_find_by_token(&server->group_mgr, payload->invite_token);
    
    if (!group) {
        LOG_WARN("Invalid invite token: %s", payload->invite_token);
        
        message_t reject;
        memset(&reject, 0, sizeof(reject));
        message_header_init(&reject.header, MSG_GROUP_REJECTED);
        strncpy(reject.header.sender_id, "relay", MAX_ID_LENGTH - 1);
        strncpy(reject.header.target_id, client->id, MAX_ID_LENGTH - 1);
        return relay_send_to_client(server, client_index, &reject);
    }
    
    // Check if already a member
    if (group_is_member(group, client->id)) {
        LOG_WARN("Client %s is already a member of group %s", 
                 client->id, group->group_id);
        
        message_t nack;
        memset(&nack, 0, sizeof(nack));
        message_header_init(&nack.header, MSG_NACK);
        strncpy(nack.header.sender_id, "relay", MAX_ID_LENGTH - 1);
        strncpy(nack.header.target_id, client->id, MAX_ID_LENGTH - 1);
        return relay_send_to_client(server, client_index, &nack);
    }
    
    // Create pending join request
    pending_join_t* pending = group_create_join_request(group, client->id, 
                                                        client->ip, client->port);
    if (!pending) {
        message_t nack;
        memset(&nack, 0, sizeof(nack));
        message_header_init(&nack.header, MSG_NACK);
        strncpy(nack.header.sender_id, "relay", MAX_ID_LENGTH - 1);
        strncpy(nack.header.target_id, client->id, MAX_ID_LENGTH - 1);
        return relay_send_to_client(server, client_index, &nack);
    }
    
    // Send vote request to all existing members
    relay_send_vote_request_to_members(server, group, pending);
    
    // Send ACK to requester (waiting for votes)
    message_t ack;
    memset(&ack, 0, sizeof(ack));
    message_header_init(&ack.header, MSG_ACK);
    strncpy(ack.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(ack.header.target_id, client->id, MAX_ID_LENGTH - 1);
    
    LOG_INFO("Join request created, waiting for %d votes", pending->votes_needed);
    
    return relay_send_to_client(server, client_index, &ack);
}

int relay_handle_group_vote(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];
    payload_group_vote_t* payload = (payload_group_vote_t*)msg->payload;
    
    LOG_INFO("Vote received from %s: %s for request %s", 
             client->id, payload->approved ? "YES" : "NO", payload->request_id);
    
    // Find the group
    group_t* group = group_find_by_id(&server->group_mgr, payload->group_id);
    if (!group) {
        LOG_WARN("Group not found: %s", payload->group_id);
        return -1;
    }
    
    // Register the vote
    int result = group_register_vote(group, payload->request_id, 
                                     client->id, payload->approved);
    if (result < 0) {
        LOG_WARN("Failed to register vote: %d", result);
        return result;
    }
    
    // Check if voting is complete
    int vote_result = group_check_vote_result(group, payload->request_id);
    
    if (vote_result != 0) {
        pending_join_t* pending = group_find_pending_join(group, payload->request_id);
        if (!pending) return -1;
        
        // Find the requester
        int requester_index = relay_find_client_index_by_id(server, pending->requester_id);
        
        if (vote_result == 1) {
            // APPROVED - add member to group
            LOG_INFO("Join request %s APPROVED for %s", 
                     payload->request_id, pending->requester_id);
            
            group_add_member(group, pending->requester_id,
                           pending->requester_ip, pending->requester_port, false);
            
            // Update client's group_id
            if (requester_index >= 0) {
                strncpy(server->clients[requester_index].group_id, 
                       group->group_id, MAX_ID_LENGTH - 1);
                
                // Send approval message
                message_t approved;
                memset(&approved, 0, sizeof(approved));
                message_header_init(&approved.header, MSG_GROUP_APPROVED);
                strncpy(approved.header.sender_id, "relay", MAX_ID_LENGTH - 1);
                strncpy(approved.header.target_id, pending->requester_id, MAX_ID_LENGTH - 1);
                
                payload_group_result_t* res = (payload_group_result_t*)approved.payload;
                strncpy(res->group_id, group->group_id, MAX_ID_LENGTH - 1);
                strncpy(res->group_name, group->group_name, MAX_GROUP_NAME - 1);
                res->member_count = group->member_count;
                approved.header.payload_length = sizeof(payload_group_result_t);
                
                relay_send_to_client(server, requester_index, &approved);
                
                // Send peer list
                relay_send_group_info(server, requester_index, group);
            }
            
            // Regenerate invite token for security
            group_regenerate_token(group);
            
        } else {
            // REJECTED
            LOG_INFO("Join request %s REJECTED for %s", 
                     payload->request_id, pending->requester_id);
            
            if (requester_index >= 0) {
                message_t rejected;
                memset(&rejected, 0, sizeof(rejected));
                message_header_init(&rejected.header, MSG_GROUP_REJECTED);
                strncpy(rejected.header.sender_id, "relay", MAX_ID_LENGTH - 1);
                strncpy(rejected.header.target_id, pending->requester_id, MAX_ID_LENGTH - 1);
                
                payload_group_result_t* res = (payload_group_result_t*)rejected.payload;
                strncpy(res->group_id, group->group_id, MAX_ID_LENGTH - 1);
                rejected.header.payload_length = sizeof(payload_group_result_t);
                
                relay_send_to_client(server, requester_index, &rejected);
            }
        }
        
        // Cleanup pending request
        group_cleanup_pending(group, payload->request_id);
    }
    
    return 0;
}

int relay_handle_group_leave(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];
    payload_group_leave_t* payload = (payload_group_leave_t*)msg->payload;
    
    LOG_INFO("Client %s leaving group %s", client->id, payload->group_id);
    
    group_t* group = group_find_by_id(&server->group_mgr, payload->group_id);
    if (!group) {
        return -1;
    }
    
    group_remove_member(group, client->id);
    memset(client->group_id, 0, sizeof(client->group_id));
    
    // If group is empty, destroy it
    if (group->member_count == 0) {
        LOG_INFO("Group %s is empty, destroying (ephemeral)", group->group_id);
        group_destroy(&server->group_mgr, payload->group_id);
    }
    
    // Send ACK
    message_t ack;
    memset(&ack, 0, sizeof(ack));
    message_header_init(&ack.header, MSG_ACK);
    strncpy(ack.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(ack.header.target_id, client->id, MAX_ID_LENGTH - 1);
    
    return relay_send_to_client(server, client_index, &ack);
}

int relay_handle_group_invite(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];
    payload_invite_request_t* payload = (payload_invite_request_t*)msg->payload;
    
    LOG_INFO("Client %s requesting new invite token for group %s", 
             client->id, payload->group_id);
    
    group_t* group = group_find_by_id(&server->group_mgr, payload->group_id);
    if (!group || !group_is_member(group, client->id)) {
        message_t nack;
        memset(&nack, 0, sizeof(nack));
        message_header_init(&nack.header, MSG_NACK);
        strncpy(nack.header.sender_id, "relay", MAX_ID_LENGTH - 1);
        strncpy(nack.header.target_id, client->id, MAX_ID_LENGTH - 1);
        return relay_send_to_client(server, client_index, &nack);
    }
    
    // Regenerate token
    group_regenerate_token(group);
    
    // Send new token
    message_t response;
    memset(&response, 0, sizeof(response));
    message_header_init(&response.header, MSG_ACK);
    strncpy(response.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(response.header.target_id, client->id, MAX_ID_LENGTH - 1);
    
    payload_invite_response_t* resp = (payload_invite_response_t*)response.payload;
    strncpy(resp->group_id, group->group_id, MAX_ID_LENGTH - 1);
    strncpy(resp->invite_token, group->invite_token, INVITE_TOKEN_LENGTH - 1);
    response.header.payload_length = sizeof(payload_invite_response_t);
    
    return relay_send_to_client(server, client_index, &response);
}

// ============================================
// GROUP UTILITIES
// ============================================

int relay_send_vote_request_to_members(relay_server_t* server, group_t* group,
                                       pending_join_t* pending) {
    int sent = 0;
    
    for (int i = 0; i < group->member_count; i++) {
        int client_index = relay_find_client_index_by_id(server, 
                                                         group->members[i].client_id);
        if (client_index < 0) continue;
        
        message_t vote_req;
        memset(&vote_req, 0, sizeof(vote_req));
        message_header_init(&vote_req.header, MSG_GROUP_VOTE_REQ);
        strncpy(vote_req.header.sender_id, "relay", MAX_ID_LENGTH - 1);
        strncpy(vote_req.header.target_id, group->members[i].client_id, MAX_ID_LENGTH - 1);
        
        payload_vote_request_t* payload = (payload_vote_request_t*)vote_req.payload;
        strncpy(payload->group_id, group->group_id, MAX_ID_LENGTH - 1);
        strncpy(payload->requester_id, pending->requester_id, MAX_ID_LENGTH - 1);
        strncpy(payload->request_id, pending->request_id, MAX_ID_LENGTH - 1);
        vote_req.header.payload_length = sizeof(payload_vote_request_t);
        
        if (relay_send_to_client(server, client_index, &vote_req) == 0) {
            sent++;
        }
    }
    
    LOG_INFO("Sent vote request to %d members", sent);
    return sent;
}

int relay_send_group_info(relay_server_t* server, int client_index, group_t* group) {
    message_t info;
    memset(&info, 0, sizeof(info));
    message_header_init(&info.header, MSG_GROUP_INFO);
    strncpy(info.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(info.header.target_id, server->clients[client_index].id, MAX_ID_LENGTH - 1);
    
    payload_group_info_t* payload = (payload_group_info_t*)info.payload;
    strncpy(payload->group_id, group->group_id, MAX_ID_LENGTH - 1);
    payload->peer_count = group->member_count;
    
    for (int i = 0; i < group->member_count && i < MAX_GROUP_MEMBERS; i++) {
        strncpy(payload->peers[i].id, group->members[i].client_id, MAX_ID_LENGTH - 1);
        strncpy(payload->peers[i].ip, group->members[i].ip, sizeof(payload->peers[i].ip) - 1);
        payload->peers[i].port = group->members[i].port;
    }
    
    info.header.payload_length = sizeof(payload_group_info_t);
    
    LOG_INFO("Sending group info to %s (%d peers)", 
             server->clients[client_index].id, payload->peer_count);
    
    return relay_send_to_client(server, client_index, &info);
}