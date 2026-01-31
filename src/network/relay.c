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
                
                // Read data
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
                    
                    // Process message
                    LOG_DEBUG("Received %zd bytes from client %s", 
                             bytes, server->clients[i].id);
                    
                    // Check if we have a complete message
                    if (bytes >= (ssize_t)sizeof(message_header_t)) {
                        message_t* msg = (message_t*)buffer;
                        
                        // Validate message
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
    
    // Configure client
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
// HANDLERS
// ============================================

int relay_handle_ping(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];
    
    // Update last_ping
    client->last_ping = get_timestamp_ms();
    
    // Create PONG response
    message_t pong;
    memset(&pong, 0, sizeof(pong));
    message_header_init(&pong.header, MSG_PONG);
    strncpy(pong.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(pong.header.target_id, client->id, MAX_ID_LENGTH - 1);
    
    // Copy ping payload to pong
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
    
    // Update client info
    if (strlen(payload->client_id) > 0) {
        strncpy(client->id, payload->client_id, MAX_ID_LENGTH - 1);
    }
    
    client->authenticated = true;
    client->last_ping = get_timestamp_ms();
    
    LOG_INFO("Client %s authenticated (version: %s, listen_port: %d)", 
             client->id, payload->client_version, payload->listen_port);
    
    // Send ACK
    message_t ack;
    memset(&ack, 0, sizeof(ack));
    message_header_init(&ack.header, MSG_ACK);
    strncpy(ack.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(ack.header.target_id, client->id, MAX_ID_LENGTH - 1);
    
    return relay_send_to_client(server, client_index, &ack);
}

int relay_handle_disconnect(relay_server_t* server, int client_index, message_t* msg) {
    (void)msg;  // Unused
    relay_disconnect_client(server, client_index);
    return 0;
}