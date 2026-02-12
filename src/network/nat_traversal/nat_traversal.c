#include "nat_traversal.h"
#include "stun.h"
#include "../../common/logging.h"
#include "../../common/protocol.h"
#include "../../common/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <poll.h>

// ============================================
// CONSTANTS
// ============================================
#define PUNCH_TIMEOUT_MS      5000
#define PUNCH_MAX_ATTEMPTS    5
#define PUNCH_CONNECT_TIMEOUT_MS 2000
#define SIMULTANEOUS_DELAY_MS 100
#define UDP_PUNCH_INTERVAL_MS 200
#define UDP_PUNCH_PROBE_SIZE  4    // "P2P\0"

// ============================================
// HELPERS
// ============================================

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int set_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

static int set_reuse(int fd) {
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
    return 0;
}

// Try TCP connect with timeout (non-blocking connect)
static int try_connect(const char* ip, uint16_t port,
                       uint16_t local_port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    
    set_reuse(sock);
    
    // Bind to local port if specified
    if (local_port > 0) {
        struct sockaddr_in local_addr;
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = INADDR_ANY;
        local_addr.sin_port = htons(local_port);
        
        if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
            LOG_TRACE("NAT: bind to port %u failed: %s", local_port, strerror(errno));
        }
    }
    
    set_nonblocking(sock);
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    int ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    if (ret == 0) {
        set_blocking(sock);
        return sock;
    }
    
    if (errno != EINPROGRESS) {
        close(sock);
        return -1;
    }
    
    struct pollfd pfd = { .fd = sock, .events = POLLOUT, .revents = 0 };
    ret = poll(&pfd, 1, timeout_ms);
    
    if (ret <= 0) {
        close(sock);
        return -1;
    }
    
    int sock_err = 0;
    socklen_t err_len = sizeof(sock_err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &sock_err, &err_len);
    
    if (sock_err != 0) {
        close(sock);
        return -1;
    }
    
    set_blocking(sock);
    return sock;
}

// Get local IP address
static void get_local_ip(char* ip, size_t len) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        strncpy(ip, "127.0.0.1", len);
        return;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        strncpy(ip, "127.0.0.1", len);
        return;
    }
    
    struct sockaddr_in local;
    socklen_t local_len = sizeof(local);
    getsockname(sock, (struct sockaddr*)&local, &local_len);
    inet_ntop(AF_INET, &local.sin_addr, ip, (socklen_t)len);
    
    close(sock);
}

// ============================================
// STRING HELPERS
// ============================================

const char* nat_type_string(nat_type_t type) {
    switch (type) {
        case NAT_TYPE_UNKNOWN:         return "Unknown";
        case NAT_TYPE_NONE:            return "No NAT (Public IP)";
        case NAT_TYPE_FULL_CONE:       return "Full Cone";
        case NAT_TYPE_RESTRICTED_CONE: return "Restricted Cone";
        case NAT_TYPE_PORT_RESTRICTED: return "Port Restricted";
        case NAT_TYPE_SYMMETRIC:       return "Symmetric (relay needed)";
        default:                       return "???";
    }
}

const char* punch_state_string(punch_state_t state) {
    switch (state) {
        case PUNCH_STATE_IDLE:           return "Idle";
        case PUNCH_STATE_INITIATED:      return "Initiated";
        case PUNCH_STATE_PUNCHING:       return "Punching";
        case PUNCH_STATE_CONNECTED:      return "Connected";
        case PUNCH_STATE_RELAY_FALLBACK: return "Relay Fallback";
        case PUNCH_STATE_FAILED:         return "Failed";
        default:                         return "???";
    }
}

// ============================================
// LIFECYCLE
// ============================================

int nat_manager_init(nat_manager_t* mgr, const char* relay_host, uint16_t relay_port) {
    memset(mgr, 0, sizeof(nat_manager_t));
    
    strncpy(mgr->relay_host, relay_host, sizeof(mgr->relay_host) - 1);
    mgr->relay_port = relay_port;
    mgr->udp_punch_fd = -1;
    
    get_local_ip(mgr->local_nat.local_ip, sizeof(mgr->local_nat.local_ip));
    
    pthread_mutex_init(&mgr->mutex, NULL);
    
    // Initialize punch contexts
    for (int i = 0; i < MAX_PUNCHES; i++) {
        mgr->punches[i].connected_fd = -1;
        mgr->punches[i].udp_fd = -1;
    }
    
    LOG_INFO("NAT manager initialized (local IP: %s)", mgr->local_nat.local_ip);
    return 0;
}

void nat_manager_cleanup(nat_manager_t* mgr) {
    pthread_mutex_lock(&mgr->mutex);
    
    // Close punch connections
    for (int i = 0; i < mgr->punch_count; i++) {
        if (mgr->punches[i].connected_fd >= 0) {
            close(mgr->punches[i].connected_fd);
            mgr->punches[i].connected_fd = -1;
        }
        if (mgr->punches[i].udp_fd >= 0) {
            close(mgr->punches[i].udp_fd);
            mgr->punches[i].udp_fd = -1;
        }
    }
    
    if (mgr->udp_punch_fd >= 0) {
        close(mgr->udp_punch_fd);
        mgr->udp_punch_fd = -1;
    }
    
    pthread_mutex_unlock(&mgr->mutex);
    pthread_mutex_destroy(&mgr->mutex);
    
    LOG_DEBUG("NAT manager cleaned up");
}

// ============================================
// DISCOVERY (via relay + STUN)
// ============================================

int nat_discover(nat_manager_t* mgr, int relay_socket_fd) {
    LOG_INFO("NAT: Sending discovery request to relay...");
    
    message_t msg;
    memset(&msg, 0, sizeof(msg));
    message_header_init(&msg.header, MSG_NAT_DISCOVER);
    
    // Include our local info so relay can compare
    payload_punch_request_t* payload = (payload_punch_request_t*)msg.payload;
    strncpy(payload->local_ip, mgr->local_nat.local_ip, sizeof(payload->local_ip) - 1);
    payload->local_port = mgr->local_nat.local_port;
    payload->p2p_listen_port = mgr->local_nat.local_port;
    msg.header.payload_length = sizeof(payload_punch_request_t);
    
    size_t total = sizeof(message_header_t) + msg.header.payload_length;
    ssize_t sent = send(relay_socket_fd, &msg, total, 0);
    
    if (sent <= 0) {
        LOG_ERROR("NAT: Failed to send discovery request");
        return -1;
    }
    
    return 0;
}

int nat_stun_discover(nat_manager_t* mgr) {
    LOG_INFO("NAT: Running STUN discovery...");
    
    // Create UDP socket for STUN
    int udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_fd < 0) {
        LOG_ERROR("NAT: Failed to create UDP socket for STUN");
        return -1;
    }
    
    set_reuse(udp_fd);
    
    // Bind to our P2P port so we learn the mapping for that port
    if (mgr->local_nat.local_port > 0) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(mgr->local_nat.local_port);
        bind(udp_fd, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    // Try multiple STUN servers
    stun_result_t result;
    int ret = stun_discover_multi(udp_fd, &result, 3000);
    
    close(udp_fd);
    
    if (ret == 0 && result.success) {
        pthread_mutex_lock(&mgr->mutex);
        
        strncpy(mgr->local_nat.public_ip, result.public_ip,
                sizeof(mgr->local_nat.public_ip) - 1);
        mgr->local_nat.public_port = result.public_port;
        mgr->stun_result = result;
        mgr->stun_discovered = true;
        
        // Determine NAT type
        if (strcmp(mgr->local_nat.local_ip, mgr->local_nat.public_ip) == 0) {
            mgr->local_nat.nat_type = NAT_TYPE_NONE;
        } else if (mgr->local_nat.local_port == mgr->local_nat.public_port) {
            mgr->local_nat.nat_type = NAT_TYPE_FULL_CONE;
        } else {
            mgr->local_nat.nat_type = NAT_TYPE_RESTRICTED_CONE;
        }
        
        mgr->local_nat.discovered = true;
        
        LOG_INFO("NAT: STUN discovery: %s:%u → %s:%u (type: %s)",
                 mgr->local_nat.local_ip, mgr->local_nat.local_port,
                 mgr->local_nat.public_ip, mgr->local_nat.public_port,
                 nat_type_string(mgr->local_nat.nat_type));
        
        pthread_mutex_unlock(&mgr->mutex);
        return 0;
    }
    
    LOG_WARN("NAT: STUN discovery failed");
    return -1;
}

void nat_set_info(nat_manager_t* mgr, const payload_nat_info_t* info) {
    pthread_mutex_lock(&mgr->mutex);
    
    strncpy(mgr->local_nat.public_ip, info->public_ip,
            sizeof(mgr->local_nat.public_ip) - 1);
    mgr->local_nat.public_port = info->public_port;
    mgr->local_nat.nat_type = (nat_type_t)info->nat_type;
    mgr->local_nat.discovered = true;
    
    LOG_INFO("NAT: Info set from relay: %s:%u (type: %s)",
             mgr->local_nat.public_ip, mgr->local_nat.public_port,
             nat_type_string(mgr->local_nat.nat_type));
    
    pthread_mutex_unlock(&mgr->mutex);
}

// ============================================
// UDP HOLE PUNCH
// ============================================

int nat_udp_hole_punch(nat_manager_t* mgr, punch_context_t* punch) {
    LOG_INFO("NAT: Starting UDP hole punch to %s (public: %s:%u, local: %s:%u)",
             punch->peer_id, punch->peer_public_ip, punch->peer_public_port,
             punch->peer_local_ip, punch->peer_local_port);
    
    // Create UDP socket bound to our P2P port
    int udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_fd < 0) {
        LOG_ERROR("NAT: UDP socket failed: %s", strerror(errno));
        return -1;
    }
    
    set_reuse(udp_fd);
    set_nonblocking(udp_fd);
    
    // Bind to our port
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(mgr->local_nat.local_port);
    
    if (bind(udp_fd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        LOG_WARN("NAT: UDP bind to port %u failed: %s",
                 mgr->local_nat.local_port, strerror(errno));
        // Try ephemeral port
    }
    
    punch->udp_fd = udp_fd;
    punch->state = PUNCH_STATE_PUNCHING;
    
    // Target addresses: try both public and local
    struct sockaddr_in targets[3];
    int target_count = 0;
    
    // Target 1: peer's public endpoint
    if (strlen(punch->peer_public_ip) > 0 && punch->peer_public_port > 0) {
        memset(&targets[target_count], 0, sizeof(struct sockaddr_in));
        targets[target_count].sin_family = AF_INET;
        targets[target_count].sin_port = htons(punch->peer_public_port);
        inet_pton(AF_INET, punch->peer_public_ip, &targets[target_count].sin_addr);
        target_count++;
    }
    
    // Target 2: peer's local endpoint (LAN)
    if (strlen(punch->peer_local_ip) > 0 && punch->peer_local_port > 0) {
        memset(&targets[target_count], 0, sizeof(struct sockaddr_in));
        targets[target_count].sin_family = AF_INET;
        targets[target_count].sin_port = htons(punch->peer_local_port);
        inet_pton(AF_INET, punch->peer_local_ip, &targets[target_count].sin_addr);
        target_count++;
    }
    
    // Target 3: peer's P2P listen port on public IP
    if (strlen(punch->peer_public_ip) > 0 && punch->peer_p2p_port > 0) {
        memset(&targets[target_count], 0, sizeof(struct sockaddr_in));
        targets[target_count].sin_family = AF_INET;
        targets[target_count].sin_port = htons(punch->peer_p2p_port);
        inet_pton(AF_INET, punch->peer_public_ip, &targets[target_count].sin_addr);
        target_count++;
    }
    
    if (target_count == 0) {
        LOG_ERROR("NAT: No targets for UDP punch");
        close(udp_fd);
        punch->udp_fd = -1;
        return -1;
    }
    
    // Punch loop: send probes and listen for responses
    uint8_t probe[] = "P2P";
    uint8_t recv_buf[64];
    
    uint64_t start = get_timestamp_ms();
    int attempt = 0;
    
    while ((get_timestamp_ms() - start) < PUNCH_TIMEOUT_MS && 
           attempt < PUNCH_MAX_ATTEMPTS * target_count) {
        
        // Send probe to all targets
        for (int t = 0; t < target_count; t++) {
            ssize_t sent = sendto(udp_fd, probe, sizeof(probe), 0,
                                   (struct sockaddr*)&targets[t],
                                   sizeof(struct sockaddr_in));
            if (sent > 0) {
                char target_ip[46];
                inet_ntop(AF_INET, &targets[t].sin_addr, target_ip, sizeof(target_ip));
                LOG_TRACE("NAT: UDP probe %d sent to %s:%u",
                          attempt, target_ip, ntohs(targets[t].sin_port));
            }
        }
        
        // Listen for response
        struct pollfd pfd = { .fd = udp_fd, .events = POLLIN, .revents = 0 };
        int ready = poll(&pfd, 1, UDP_PUNCH_INTERVAL_MS);
        
        if (ready > 0) {
            struct sockaddr_in from;
            socklen_t from_len = sizeof(from);
            ssize_t received = recvfrom(udp_fd, recv_buf, sizeof(recv_buf), 0,
                                         (struct sockaddr*)&from, &from_len);
            
            if (received > 0) {
                char from_ip[46];
                inet_ntop(AF_INET, &from.sin_addr, from_ip, sizeof(from_ip));
                LOG_INFO("NAT: UDP hole punch SUCCESS! Received from %s:%u",
                         from_ip, ntohs(from.sin_port));
                
                punch->state = PUNCH_STATE_CONNECTED;
                punch->connected_at = get_timestamp_ms();
                
                // Now attempt TCP connection through the punched hole
                set_blocking(udp_fd);
                return udp_fd;
            }
        }
        
        attempt++;
    }
    
    LOG_WARN("NAT: UDP hole punch failed after %d attempts", attempt);
    close(udp_fd);
    punch->udp_fd = -1;
    return -1;
}

// ============================================
// HOLE PUNCH ORCHESTRATION
// ============================================

int nat_punch_to_peer(nat_manager_t* mgr, int relay_socket_fd,
                      const char* peer_id, const char* sender_id) {
    LOG_INFO("NAT: Requesting punch to peer %s", peer_id);
    
    message_t msg;
    memset(&msg, 0, sizeof(msg));
    message_header_init(&msg.header, MSG_NAT_PUNCH_REQ);
    strncpy(msg.header.sender_id, sender_id, MAX_ID_LENGTH - 1);
    
    payload_punch_request_t* payload = (payload_punch_request_t*)msg.payload;
    strncpy(payload->target_peer_id, peer_id, MAX_ID_LENGTH - 1);
    strncpy(payload->local_ip, mgr->local_nat.local_ip, sizeof(payload->local_ip) - 1);
    payload->local_port = mgr->local_nat.local_port;
    payload->p2p_listen_port = mgr->local_nat.local_port;
    msg.header.payload_length = sizeof(payload_punch_request_t);
    
    size_t total = sizeof(message_header_t) + msg.header.payload_length;
    ssize_t sent = send(relay_socket_fd, &msg, total, 0);
    
    if (sent <= 0) {
        LOG_ERROR("NAT: Failed to send punch request");
        return -1;
    }
    
    // Add to punch tracking
    pthread_mutex_lock(&mgr->mutex);
    if (mgr->punch_count < MAX_PUNCHES) {
        punch_context_t* punch = &mgr->punches[mgr->punch_count];
        memset(punch, 0, sizeof(punch_context_t));
        strncpy(punch->peer_id, peer_id, MAX_ID_LENGTH - 1);
        punch->state = PUNCH_STATE_INITIATED;
        punch->started_at = get_timestamp_ms();
        punch->connected_fd = -1;
        punch->udp_fd = -1;
        punch->is_initiator = true;
        mgr->punch_count++;
    }
    pthread_mutex_unlock(&mgr->mutex);
    
    return 0;
}

int nat_handle_punch_instruction(nat_manager_t* mgr,
                                  const payload_punch_instruction_t* instr) {
    LOG_INFO("NAT: Punch instruction: connect to %s (pub=%s:%u, local=%s:%u, p2p=%u)",
             instr->peer_id, instr->peer_public_ip, instr->peer_public_port,
             instr->peer_local_ip, instr->peer_local_port, instr->peer_p2p_port);
    
    // Find or create punch context
    pthread_mutex_lock(&mgr->mutex);
    
    punch_context_t* punch = NULL;
    for (int i = 0; i < mgr->punch_count; i++) {
        if (strcmp(mgr->punches[i].peer_id, instr->peer_id) == 0) {
            punch = &mgr->punches[i];
            break;
        }
    }
    
    if (!punch && mgr->punch_count < MAX_PUNCHES) {
        punch = &mgr->punches[mgr->punch_count++];
        memset(punch, 0, sizeof(punch_context_t));
        strncpy(punch->peer_id, instr->peer_id, MAX_ID_LENGTH - 1);
        punch->connected_fd = -1;
        punch->udp_fd = -1;
    }
    
    if (!punch) {
        pthread_mutex_unlock(&mgr->mutex);
        LOG_ERROR("NAT: No punch slot available");
        return -1;
    }
    
    strncpy(punch->peer_public_ip, instr->peer_public_ip, sizeof(punch->peer_public_ip) - 1);
    punch->peer_public_port = instr->peer_public_port;
    strncpy(punch->peer_local_ip, instr->peer_local_ip, sizeof(punch->peer_local_ip) - 1);
    punch->peer_local_port = instr->peer_local_port;
    punch->peer_p2p_port = instr->peer_p2p_port;
    punch->is_initiator = instr->you_are_initiator;
    punch->started_at = get_timestamp_ms();
    punch->state = PUNCH_STATE_PUNCHING;
    
    pthread_mutex_unlock(&mgr->mutex);
    
    // Slight delay for non-initiator to let initiator's SYN arrive first
    if (!punch->is_initiator) {
        usleep(SIMULTANEOUS_DELAY_MS * 1000);
    }
    
    int connected_fd = -1;
    
    // Strategy 1: Try direct TCP to P2P port (works on LAN)
    LOG_DEBUG("NAT: Trying direct TCP to %s:%u...",
              instr->peer_local_ip, instr->peer_p2p_port);
    connected_fd = try_connect(instr->peer_local_ip, instr->peer_p2p_port, 0,
                                PUNCH_CONNECT_TIMEOUT_MS);
    
    if (connected_fd >= 0) {
        LOG_INFO("NAT: Direct LAN connection succeeded!");
        punch->connected_fd = connected_fd;
        punch->state = PUNCH_STATE_CONNECTED;
        return connected_fd;
    }
    
    // Strategy 2: Try direct TCP to public endpoint
    LOG_DEBUG("NAT: Trying TCP to public %s:%u...",
              instr->peer_public_ip, instr->peer_public_port);
    connected_fd = try_connect(instr->peer_public_ip, instr->peer_public_port,
                                mgr->local_nat.local_port, PUNCH_CONNECT_TIMEOUT_MS);
    
    if (connected_fd >= 0) {
        LOG_INFO("NAT: TCP punch through public endpoint succeeded!");
        punch->connected_fd = connected_fd;
        punch->state = PUNCH_STATE_CONNECTED;
        return connected_fd;
    }
    
    // Strategy 3: Try TCP to public IP on P2P port
    if (instr->peer_p2p_port != instr->peer_public_port) {
        LOG_DEBUG("NAT: Trying TCP to %s:%u (public IP, P2P port)...",
                  instr->peer_public_ip, instr->peer_p2p_port);
        connected_fd = try_connect(instr->peer_public_ip, instr->peer_p2p_port,
                                    mgr->local_nat.local_port, PUNCH_CONNECT_TIMEOUT_MS);
        
        if (connected_fd >= 0) {
            LOG_INFO("NAT: TCP to public IP P2P port succeeded!");
            punch->connected_fd = connected_fd;
            punch->state = PUNCH_STATE_CONNECTED;
            return connected_fd;
        }
    }
    
    // Strategy 4: UDP hole punch (create NAT mapping, then TCP)
    LOG_DEBUG("NAT: Attempting UDP hole punch...");
    int udp_result = nat_udp_hole_punch(mgr, punch);
    
    if (udp_result >= 0) {
        // UDP hole created — now try TCP through the same mapping
        LOG_DEBUG("NAT: UDP hole created, retrying TCP...");
        connected_fd = try_connect(instr->peer_public_ip, instr->peer_public_port,
                                    mgr->local_nat.local_port, PUNCH_CONNECT_TIMEOUT_MS);
        
        if (connected_fd >= 0) {
            LOG_INFO("NAT: TCP through UDP-punched hole succeeded!");
            punch->connected_fd = connected_fd;
            punch->state = PUNCH_STATE_CONNECTED;
            return connected_fd;
        }
    }
    
    // Strategy 5: Relay fallback for symmetric NAT
    LOG_WARN("NAT: All punch strategies failed, falling back to relay proxy");
    punch->state = PUNCH_STATE_RELAY_FALLBACK;
    
    return -1;
}

// ============================================
// RELAY FALLBACK (symmetric NAT)
// ============================================

int nat_relay_send(nat_manager_t* mgr, int relay_fd,
                   const char* peer_id, const void* data, size_t len) {
    (void)mgr;
    
    if (len > sizeof(((payload_relay_proxy_t*)0)->data)) {
        LOG_ERROR("NAT: Relay data too large (%zu bytes)", len);
        return -1;
    }
    
    message_t msg;
    memset(&msg, 0, sizeof(msg));
    message_header_init(&msg.header, MSG_NAT_RELAY_DATA);
    
    payload_relay_proxy_t* proxy = (payload_relay_proxy_t*)msg.payload;
    strncpy(proxy->target_peer_id, peer_id, MAX_ID_LENGTH - 1);
    proxy->data_length = (uint32_t)len;
    memcpy(proxy->data, data, len);
    msg.header.payload_length = sizeof(payload_relay_proxy_t);
    
    size_t total = sizeof(message_header_t) + msg.header.payload_length;
    ssize_t sent = send(relay_fd, &msg, total, 0);
    
    if (sent <= 0) {
        LOG_ERROR("NAT: Relay send failed");
        return -1;
    }
    
    LOG_TRACE("NAT: Relayed %zu bytes to %s", len, peer_id);
    return 0;
}

// ============================================
// PEER CONNECTION LOOKUP
// ============================================

int nat_get_peer_connection(nat_manager_t* mgr, const char* peer_id) {
    pthread_mutex_lock(&mgr->mutex);
    
    for (int i = 0; i < mgr->punch_count; i++) {
        if (strcmp(mgr->punches[i].peer_id, peer_id) == 0 &&
            mgr->punches[i].state == PUNCH_STATE_CONNECTED &&
            mgr->punches[i].connected_fd >= 0) {
            int fd = mgr->punches[i].connected_fd;
            pthread_mutex_unlock(&mgr->mutex);
            return fd;
        }
    }
    
    pthread_mutex_unlock(&mgr->mutex);
    return -1;
}

// ============================================
// PUBLIC WRAPPER
// ============================================

int nat_try_connect(const char* ip, uint16_t port, uint16_t local_port, int timeout_ms) {
    return try_connect(ip, port, local_port, timeout_ms);
}