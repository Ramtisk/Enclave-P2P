#include "socket_mgr.h"
#include "../common/logging.h"
#include "../common/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

// ============================================
// HELPERS
// ============================================

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// ============================================
// NON-BLOCKING SOCKET HELPERS
// ============================================

int socket_set_nonblocking(int fd) {
    if (fd < 0) return -1;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        LOG_ERROR("socket_mgr: fcntl F_GETFL failed: %s", strerror(errno));
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        LOG_ERROR("socket_mgr: fcntl F_SETFL failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int socket_set_blocking(int fd) {
    if (fd < 0) return -1;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == -1) return -1;
    return 0;
}

int socket_set_reuse(int fd) {
    if (fd < 0) return -1;
    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        LOG_WARN("socket_mgr: SO_REUSEADDR failed: %s", strerror(errno));
    }
#ifdef SO_REUSEPORT
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        LOG_TRACE("socket_mgr: SO_REUSEPORT not available");
    }
#endif
    return 0;
}

int socket_set_nodelay(int fd) {
    if (fd < 0) return -1;
    int opt = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {
        LOG_WARN("socket_mgr: TCP_NODELAY failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int socket_set_keepalive(int fd, int idle_sec, int interval_sec, int max_probes) {
    if (fd < 0) return -1;
    
    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0) {
        LOG_WARN("socket_mgr: SO_KEEPALIVE failed: %s", strerror(errno));
        return -1;
    }

#ifdef TCP_KEEPIDLE
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle_sec, sizeof(idle_sec)) < 0) {
        LOG_TRACE("socket_mgr: TCP_KEEPIDLE not supported");
    }
#else
    (void)idle_sec;
#endif

#ifdef TCP_KEEPINTVL
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval_sec, sizeof(interval_sec)) < 0) {
        LOG_TRACE("socket_mgr: TCP_KEEPINTVL not supported");
    }
#else
    (void)interval_sec;
#endif

#ifdef TCP_KEEPCNT
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &max_probes, sizeof(max_probes)) < 0) {
        LOG_TRACE("socket_mgr: TCP_KEEPCNT not supported");
    }
#else
    (void)max_probes;
#endif

    return 0;
}

int socket_set_send_buffer(int fd, int size) {
    return setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
}

int socket_set_recv_buffer(int fd, int size) {
    return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
}

int socket_get_error(int fd) {
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        return errno;
    }
    return error;
}

// ============================================
// CONNECTION WITH TIMEOUT (non-blocking connect)
// ============================================

int socket_connect_timeout(const char* host, uint16_t port, 
                           uint16_t local_port, int timeout_ms) {
    if (!host || port == 0) return -1;

    // Resolve host
    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    int gai = getaddrinfo(host, port_str, &hints, &result);
    if (gai != 0) {
        LOG_ERROR("socket_mgr: getaddrinfo(%s): %s", host, gai_strerror(gai));
        return -1;
    }

    // Create socket
    int fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (fd < 0) {
        LOG_ERROR("socket_mgr: socket(): %s", strerror(errno));
        freeaddrinfo(result);
        return -1;
    }

    socket_set_reuse(fd);

    // Bind to local port if specified (for NAT punch)
    if (local_port > 0) {
        struct sockaddr_in local_addr;
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = INADDR_ANY;
        local_addr.sin_port = htons(local_port);

        if (bind(fd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
            LOG_TRACE("socket_mgr: bind to port %u failed: %s", 
                      local_port, strerror(errno));
            // Non-fatal: continue without binding
        }
    }

    // Set non-blocking for timeout
    socket_set_nonblocking(fd);

    // Initiate connect
    int ret = connect(fd, result->ai_addr, result->ai_addrlen);
    freeaddrinfo(result);

    if (ret == 0) {
        // Immediate connection (unlikely for non-blocking)
        socket_set_blocking(fd);
        socket_set_nodelay(fd);
        LOG_DEBUG("socket_mgr: Immediate connect to %s:%u", host, port);
        return fd;
    }

    if (errno != EINPROGRESS) {
        LOG_DEBUG("socket_mgr: connect(%s:%u) failed: %s", host, port, strerror(errno));
        close(fd);
        return -1;
    }

    // Wait for connection with timeout
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;

    ret = poll(&pfd, 1, timeout_ms);

    if (ret <= 0) {
        if (ret == 0) {
            LOG_DEBUG("socket_mgr: connect(%s:%u) timeout (%dms)", 
                      host, port, timeout_ms);
        } else {
            LOG_DEBUG("socket_mgr: poll error: %s", strerror(errno));
        }
        close(fd);
        return -1;
    }

    // Check for connection error
    int sock_err = socket_get_error(fd);
    if (sock_err != 0) {
        LOG_DEBUG("socket_mgr: connect(%s:%u) failed: %s", 
                  host, port, strerror(sock_err));
        close(fd);
        return -1;
    }

    // Success — set back to blocking
    socket_set_blocking(fd);
    socket_set_nodelay(fd);

    LOG_DEBUG("socket_mgr: Connected to %s:%u (fd=%d)", host, port, fd);
    return fd;
}

// ============================================
// UDP SOCKET CREATION
// ============================================

int socket_create_udp(uint16_t local_port) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        LOG_ERROR("socket_mgr: UDP socket(): %s", strerror(errno));
        return -1;
    }

    socket_set_reuse(fd);

    if (local_port > 0) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(local_port);

        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            LOG_ERROR("socket_mgr: UDP bind(%u): %s", local_port, strerror(errno));
            close(fd);
            return -1;
        }
    }

    LOG_DEBUG("socket_mgr: UDP socket created (fd=%d, port=%u)", fd, local_port);
    return fd;
}

// ============================================
// TCP LISTENER
// ============================================

int socket_create_listener(uint16_t port, int backlog) {
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        LOG_ERROR("socket_mgr: listener socket(): %s", strerror(errno));
        return -1;
    }

    socket_set_reuse(fd);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("socket_mgr: bind(%u): %s", port, strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, backlog) < 0) {
        LOG_ERROR("socket_mgr: listen(): %s", strerror(errno));
        close(fd);
        return -1;
    }

    LOG_INFO("socket_mgr: Listening on port %u (fd=%d)", port, fd);
    return fd;
}

// ============================================
// SEND/RECV WITH TIMEOUT
// ============================================

ssize_t socket_send_all(int fd, const void* data, size_t len, int timeout_ms) {
    const uint8_t* ptr = (const uint8_t*)data;
    size_t remaining = len;
    uint64_t deadline = get_timestamp_ms() + (uint64_t)timeout_ms;

    while (remaining > 0) {
        if (timeout_ms > 0 && get_timestamp_ms() >= deadline) {
            LOG_WARN("socket_mgr: send_all timeout");
            return (ssize_t)(len - remaining);
        }

        struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
        int ready = poll(&pfd, 1, timeout_ms > 0 ? 
                         (int)(deadline - get_timestamp_ms()) : 5000);
        if (ready <= 0) {
            if (ready == 0) continue;
            return -1;
        }

        ssize_t sent = send(fd, ptr, remaining, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (errno == EINTR) continue;
            LOG_ERROR("socket_mgr: send: %s", strerror(errno));
            return -1;
        }
        if (sent == 0) return (ssize_t)(len - remaining);

        ptr += sent;
        remaining -= (size_t)sent;
    }

    return (ssize_t)len;
}

ssize_t socket_recv_all(int fd, void* buf, size_t len, int timeout_ms) {
    uint8_t* ptr = (uint8_t*)buf;
    size_t remaining = len;
    uint64_t deadline = get_timestamp_ms() + (uint64_t)timeout_ms;

    while (remaining > 0) {
        int time_left = timeout_ms > 0 ? 
                        (int)(deadline - get_timestamp_ms()) : 5000;
        if (timeout_ms > 0 && time_left <= 0) {
            LOG_WARN("socket_mgr: recv_all timeout");
            return (ssize_t)(len - remaining);
        }

        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        int ready = poll(&pfd, 1, time_left);
        if (ready <= 0) {
            if (ready == 0) continue;
            return -1;
        }

        ssize_t received = recv(fd, ptr, remaining, 0);
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (errno == EINTR) continue;
            return -1;
        }
        if (received == 0) return (ssize_t)(len - remaining); // EOF

        ptr += received;
        remaining -= (size_t)received;
    }

    return (ssize_t)len;
}

ssize_t socket_recv_timeout(int fd, void* buf, size_t len, int timeout_ms) {
    struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
    int ready = poll(&pfd, 1, timeout_ms);

    if (ready <= 0) return ready; // 0 = timeout, -1 = error

    return recv(fd, buf, len, 0);
}

// ============================================
// CONNECTION MANAGER
// ============================================

void conn_manager_init(connection_manager_t* mgr) {
    memset(mgr, 0, sizeof(connection_manager_t));
    pthread_mutex_init(&mgr->mutex, NULL);
    LOG_DEBUG("socket_mgr: Connection manager initialized");
}

void conn_manager_cleanup(connection_manager_t* mgr) {
    pthread_mutex_lock(&mgr->mutex);
    
    for (int i = 0; i < mgr->count; i++) {
        if (mgr->connections[i].fd >= 0 && 
            mgr->connections[i].state != CONN_STATE_CLOSED) {
            close(mgr->connections[i].fd);
            mgr->connections[i].fd = -1;
            mgr->connections[i].state = CONN_STATE_CLOSED;
        }
    }
    mgr->count = 0;
    
    pthread_mutex_unlock(&mgr->mutex);
    pthread_mutex_destroy(&mgr->mutex);
}

int conn_manager_add(connection_manager_t* mgr, int fd, const char* peer_id,
                     const char* ip, uint16_t port) {
    pthread_mutex_lock(&mgr->mutex);
    
    if (mgr->count >= CONN_MANAGER_MAX) {
        LOG_WARN("socket_mgr: Connection manager full");
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    managed_connection_t* conn = &mgr->connections[mgr->count];
    memset(conn, 0, sizeof(managed_connection_t));
    
    conn->fd = fd;
    strncpy(conn->peer_id, peer_id, MAX_ID_LENGTH - 1);
    strncpy(conn->ip, ip, sizeof(conn->ip) - 1);
    conn->port = port;
    conn->state = CONN_STATE_CONNECTED;
    conn->connected_at = get_timestamp_ms();
    conn->last_activity = conn->connected_at;
    conn->timeout_ms = CONNECTION_TIMEOUT_MS;
    
    mgr->count++;
    
    LOG_DEBUG("socket_mgr: Added connection %s (fd=%d, %s:%u) [%d total]",
              peer_id, fd, ip, port, mgr->count);
    
    pthread_mutex_unlock(&mgr->mutex);
    return 0;
}

int conn_manager_remove(connection_manager_t* mgr, const char* peer_id) {
    pthread_mutex_lock(&mgr->mutex);
    
    for (int i = 0; i < mgr->count; i++) {
        if (strcmp(mgr->connections[i].peer_id, peer_id) == 0) {
            if (mgr->connections[i].fd >= 0) {
                close(mgr->connections[i].fd);
            }
            // Shift remaining
            for (int j = i; j < mgr->count - 1; j++) {
                mgr->connections[j] = mgr->connections[j + 1];
            }
            mgr->count--;
            pthread_mutex_unlock(&mgr->mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&mgr->mutex);
    return -1;
}

managed_connection_t* conn_manager_find(connection_manager_t* mgr, 
                                         const char* peer_id) {
    for (int i = 0; i < mgr->count; i++) {
        if (strcmp(mgr->connections[i].peer_id, peer_id) == 0) {
            return &mgr->connections[i];
        }
    }
    return NULL;
}

int conn_manager_check_timeouts(connection_manager_t* mgr) {
    pthread_mutex_lock(&mgr->mutex);
    
    uint64_t now = get_timestamp_ms();
    int timed_out = 0;
    
    for (int i = 0; i < mgr->count; i++) {
        managed_connection_t* conn = &mgr->connections[i];
        if (conn->state == CONN_STATE_CONNECTED &&
            conn->timeout_ms > 0 &&
            (now - conn->last_activity) > (uint64_t)conn->timeout_ms) {
            
            LOG_WARN("socket_mgr: Connection to %s timed out (%u ms idle)",
                     conn->peer_id, (unsigned)(now - conn->last_activity));
            conn->state = CONN_STATE_TIMEOUT;
            timed_out++;
        }
    }
    
    pthread_mutex_unlock(&mgr->mutex);
    return timed_out;
}

void conn_manager_touch(connection_manager_t* mgr, const char* peer_id) {
    pthread_mutex_lock(&mgr->mutex);
    managed_connection_t* conn = conn_manager_find(mgr, peer_id);
    if (conn) {
        conn->last_activity = get_timestamp_ms();
    }
    pthread_mutex_unlock(&mgr->mutex);
}

// ============================================
// UTILITY
// ============================================

int socket_get_local_addr(int fd, char* ip_out, size_t ip_len, uint16_t* port_out) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    
    if (getsockname(fd, (struct sockaddr*)&addr, &len) < 0) {
        return -1;
    }
    
    if (ip_out) {
        inet_ntop(AF_INET, &addr.sin_addr, ip_out, (socklen_t)ip_len);
    }
    if (port_out) {
        *port_out = ntohs(addr.sin_port);
    }
    return 0;
}

int socket_get_peer_addr(int fd, char* ip_out, size_t ip_len, uint16_t* port_out) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    
    if (getpeername(fd, (struct sockaddr*)&addr, &len) < 0) {
        return -1;
    }
    
    if (ip_out) {
        inet_ntop(AF_INET, &addr.sin_addr, ip_out, (socklen_t)ip_len);
    }
    if (port_out) {
        *port_out = ntohs(addr.sin_port);
    }
    return 0;
}

const char* conn_state_string(conn_state_t state) {
    switch (state) {
        case CONN_STATE_DISCONNECTED: return "DISCONNECTED";
        case CONN_STATE_CONNECTING:   return "CONNECTING";
        case CONN_STATE_CONNECTED:    return "CONNECTED";
        case CONN_STATE_TLS_HANDSHAKE: return "TLS_HANDSHAKE";
        case CONN_STATE_AUTHENTICATED: return "AUTHENTICATED";
        case CONN_STATE_TIMEOUT:      return "TIMEOUT";
        case CONN_STATE_ERROR:        return "ERROR";
        case CONN_STATE_CLOSED:       return "CLOSED";
        default:                      return "UNKNOWN";
    }
}