#ifndef P2P_SOCKET_MGR_H
#define P2P_SOCKET_MGR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>
#include <sys/types.h>
#include "../common/config.h"

// ============================================
// CONNECTION STATES
// ============================================
typedef enum {
    CONN_STATE_DISCONNECTED = 0,
    CONN_STATE_CONNECTING,
    CONN_STATE_CONNECTED,
    CONN_STATE_TLS_HANDSHAKE,
    CONN_STATE_AUTHENTICATED,
    CONN_STATE_TIMEOUT,
    CONN_STATE_ERROR,
    CONN_STATE_CLOSED
} conn_state_t;

// ============================================
// MANAGED CONNECTION
// ============================================
typedef struct {
    int fd;
    char peer_id[MAX_ID_LENGTH];
    char ip[46];
    uint16_t port;
    conn_state_t state;
    
    uint64_t connected_at;
    uint64_t last_activity;
    int timeout_ms;
    
    // TLS state (opaque pointer, set by tls_helper)
    void* tls_ctx;
    bool tls_enabled;
    
    // Stats
    uint64_t bytes_sent;
    uint64_t bytes_received;
} managed_connection_t;

// ============================================
// CONNECTION MANAGER
// ============================================
#define CONN_MANAGER_MAX 128

typedef struct {
    managed_connection_t connections[CONN_MANAGER_MAX];
    int count;
    pthread_mutex_t mutex;
} connection_manager_t;

// ============================================
// NON-BLOCKING SOCKET HELPERS
// ============================================
int socket_set_nonblocking(int fd);
int socket_set_blocking(int fd);
int socket_set_reuse(int fd);
int socket_set_nodelay(int fd);
int socket_set_keepalive(int fd, int idle_sec, int interval_sec, int max_probes);
int socket_set_send_buffer(int fd, int size);
int socket_set_recv_buffer(int fd, int size);
int socket_get_error(int fd);

// ============================================
// CONNECTION WITH TIMEOUT
// ============================================
// Returns fd on success, -1 on failure
// local_port = 0 for ephemeral, >0 to bind (NAT punch)
int socket_connect_timeout(const char* host, uint16_t port, 
                           uint16_t local_port, int timeout_ms);

// ============================================
// SOCKET CREATION
// ============================================
int socket_create_udp(uint16_t local_port);
int socket_create_listener(uint16_t port, int backlog);

// ============================================
// SEND/RECV WITH TIMEOUT
// ============================================
// send_all: sends exactly len bytes or fails
ssize_t socket_send_all(int fd, const void* data, size_t len, int timeout_ms);
// recv_all: receives exactly len bytes or fails
ssize_t socket_recv_all(int fd, void* buf, size_t len, int timeout_ms);
// recv_timeout: single recv with timeout
ssize_t socket_recv_timeout(int fd, void* buf, size_t len, int timeout_ms);

// ============================================
// CONNECTION MANAGER
// ============================================
void conn_manager_init(connection_manager_t* mgr);
void conn_manager_cleanup(connection_manager_t* mgr);
int  conn_manager_add(connection_manager_t* mgr, int fd, const char* peer_id,
                      const char* ip, uint16_t port);
int  conn_manager_remove(connection_manager_t* mgr, const char* peer_id);
managed_connection_t* conn_manager_find(connection_manager_t* mgr, const char* peer_id);
int  conn_manager_check_timeouts(connection_manager_t* mgr);
void conn_manager_touch(connection_manager_t* mgr, const char* peer_id);

// ============================================
// UTILITY
// ============================================
int socket_get_local_addr(int fd, char* ip_out, size_t ip_len, uint16_t* port_out);
int socket_get_peer_addr(int fd, char* ip_out, size_t ip_len, uint16_t* port_out);
const char* conn_state_string(conn_state_t state);

#endif // P2P_SOCKET_MGR_H