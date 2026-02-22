#define _POSIX_C_SOURCE 200809L
#include "relay.h"
#include "relay_dispatch.h"
#include "common/logging.h"
#include "common/config.h"

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
// INTERNAL HELPERS
// ============================================

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void generate_client_id(char* id, size_t len) {
    static int counter = 0;
    snprintf(id, len, "client_%d_%lu", ++counter, get_timestamp_ms() % 10000);
}

// ============================================
// LIFECYCLE
// ============================================

/*  Function: relay_init
    Description:
    Creates the listening TCP socket, binds, listens, sets non-blocking.
    Initializes client slots and the group manager.

    Parameters:
    - server: Relay server struct to initialize.
    - port: TCP port to listen on.

    Returns:
    - 0 on success, -1 on failure.
*/
int relay_init(relay_server_t* server, uint16_t port) {
    memset(server, 0, sizeof(relay_server_t));
    server->port = port;
    server->running = false;
    server->client_count = 0;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        server->clients[i].socket_fd = -1;
    }

    group_manager_init(&server->group_mgr);

    server->server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->server_fd < 0) {
        LOG_ERROR("Failed to create socket: %s", strerror(errno));
        return -1;
    }

    int opt = 1;
    setsockopt(server->server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

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

    if (listen(server->server_fd, 10) < 0) {
        LOG_ERROR("Failed to listen: %s", strerror(errno));
        close(server->server_fd);
        return -1;
    }

    set_nonblocking(server->server_fd);

    LOG_INFO("Relay initialized on port %d", port);
    return 0;
}

/*  Function: relay_start
    Description:
    Main event loop. Uses select() to multiplex the listening socket
    and all connected client sockets. Accepts new clients, reads
    incoming messages and dispatches them, and times out idle clients.

    Parameters:
    - server: Initialized relay server.

    Returns:
    - 0 when stopped cleanly.
*/
int relay_start(relay_server_t* server) {
    server->running = true;
    LOG_INFO("Relay starting main loop...");

    fd_set read_fds;
    struct timeval timeout;

    while (server->running) {
        FD_ZERO(&read_fds);
        FD_SET(server->server_fd, &read_fds);
        int max_fd = server->server_fd;

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (server->clients[i].socket_fd > 0) {
                FD_SET(server->clients[i].socket_fd, &read_fds);
                if (server->clients[i].socket_fd > max_fd) {
                    max_fd = server->clients[i].socket_fd;
                }
            }
        }

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);

        if (activity < 0 && errno != EINTR) {
            LOG_ERROR("Select error: %s", strerror(errno));
            continue;
        }

        // ── Accept new connections ──
        if (FD_ISSET(server->server_fd, &read_fds)) {
            relay_accept_client(server);
        }

        // ── Read from existing clients ──
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
                        LOG_ERROR("Read error from %s: %s",
                                  server->clients[i].id, strerror(errno));
                    }
                    relay_disconnect_client(server, i);
                } else {
                    server->total_bytes_received += bytes;

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

        // ── Timeout check ──
        uint64_t now = get_timestamp_ms();
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (server->clients[i].socket_fd > 0) {
                uint64_t diff = now - server->clients[i].last_ping;
                if (diff > CONNECTION_TIMEOUT_MS) {
                    LOG_WARN("Client %s timeout (%lu ms)",
                             server->clients[i].id, diff);
                    relay_disconnect_client(server, i);
                }
            }
        }
    }

    return 0;
}

/*  Function: relay_stop
    Description:
    Signals the main loop to exit.

    Parameters:
    - server: Running relay server.
*/
void relay_stop(relay_server_t* server) {
    LOG_INFO("Stopping relay...");
    server->running = false;
}

/*  Function: relay_cleanup
    Description:
    Disconnects all clients, cleans up the group manager, and closes
    the listening socket. Logs final statistics.

    Parameters:
    - server: Relay server to clean up.
*/
void relay_cleanup(relay_server_t* server) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (server->clients[i].socket_fd > 0) {
            relay_disconnect_client(server, i);
        }
    }

    group_manager_cleanup(&server->group_mgr);

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
// CLIENT ACCEPT / DISCONNECT
// ============================================

/*  Function: relay_accept_client
    Description:
    Accepts a new TCP connection, assigns it to the first free client slot,
    sets non-blocking, records IP/port/timestamp, and generates a temporary ID.

    Parameters:
    - server: Relay server.

    Returns:
    - Slot index on success, -1 on failure or server full.
*/
int relay_accept_client(relay_server_t* server) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    int client_fd = accept(server->server_fd,
                           (struct sockaddr*)&client_addr, &addr_len);
    if (client_fd < 0) {
        if (errno != EWOULDBLOCK && errno != EAGAIN) {
            LOG_ERROR("Accept error: %s", strerror(errno));
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

    LOG_INFO("New client: %s (%s:%d) [slot %d] [total: %d]",
             client->id, client->ip, client->port, slot, server->client_count);

    return slot;
}

/*  Function: relay_disconnect_client
    Description:
    Removes the client from its group (destroying the group if empty),
    closes the socket, clears the slot, and decrements the count.

    Parameters:
    - server: Relay server.
    - client_index: Slot index of the client to disconnect.
*/
void relay_disconnect_client(relay_server_t* server, int client_index) {
    if (client_index < 0 || client_index >= MAX_CLIENTS) return;

    client_connection_t* client = &server->clients[client_index];
    if (client->socket_fd <= 0) return;

    LOG_INFO("Disconnecting client %s", client->id);

    // Remove from group if applicable
    if (strlen(client->group_id) > 0) {
        group_t* group = group_find_by_id(&server->group_mgr, client->group_id);
        if (group) {
            group_remove_member(group, client->id);
            if (group->member_count == 0) {
                LOG_INFO("Group %s empty, destroying", group->group_id);
                group_destroy(&server->group_mgr, group->group_id);
            }
        }
    }

    close(client->socket_fd);
    client->socket_fd = -1;
    server->client_count--;

    LOG_INFO("Active clients: %d", server->client_count);
}