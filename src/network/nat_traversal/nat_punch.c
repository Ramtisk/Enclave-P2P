#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "nat_punch.h"
#include "common/logging.h"
#include "common/protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// ============================================
// CONSTANTS
// ============================================
#define PUNCH_TIMEOUT_MS          5000
#define PUNCH_MAX_ATTEMPTS        5
#define PUNCH_CONNECT_TIMEOUT_MS  2000
#define SIMULTANEOUS_DELAY_MS     100
#define UDP_PUNCH_INTERVAL_MS     200

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

// ============================================
// TCP CONNECT WITH TIMEOUT
// ============================================

/*  Function: nat_try_connect
    Description:
    Creates a TCP socket, optionally binds to local_port, and performs
    a non-blocking connect with a poll-based timeout.

    Parameters:
    - ip: Destination IPv4 address.
    - port: Destination port.
    - local_port: Local port to bind (0 = ephemeral).
    - timeout_ms: Connect timeout in milliseconds.

    Returns:
    - Connected socket fd on success, -1 on failure.
*/
int nat_try_connect(const char* ip, uint16_t port,
                    uint16_t local_port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    set_reuse(sock);

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

// ============================================
// UDP HOLE PUNCH
// ============================================

/*  Function: nat_udp_hole_punch
    Description:
    Creates a NAT mapping by sending UDP probes to the peer's known
    endpoints and listening for a response.

    Parameters:
    - mgr: NAT manager (for local_port).
    - punch: Punch context with peer endpoint info.

    Returns:
    - UDP fd on success, -1 on failure.

    Steps:
    1. Creates and binds a UDP socket to our P2P port.
    2. Builds target list: public endpoint, LAN endpoint, P2P port on public IP.
    3. Sends "P2P" probe packets in a loop.
    4. Polls for incoming response between sends.
    5. Returns fd on first received packet.
*/
int nat_udp_hole_punch(nat_manager_t* mgr, punch_context_t* punch) {
    LOG_INFO("NAT: Starting UDP hole punch to %s (public: %s:%u, local: %s:%u)",
             punch->peer_id, punch->peer_public_ip, punch->peer_public_port,
             punch->peer_local_ip, punch->peer_local_port);

    int udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_fd < 0) {
        LOG_ERROR("NAT: UDP socket failed: %s", strerror(errno));
        return -1;
    }

    set_reuse(udp_fd);
    set_nonblocking(udp_fd);

    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(mgr->local_nat.local_port);

    if (bind(udp_fd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        LOG_WARN("NAT: UDP bind to port %u failed: %s",
                 mgr->local_nat.local_port, strerror(errno));
    }

    punch->udp_fd = udp_fd;
    punch->state = PUNCH_STATE_PUNCHING;

    // Build target list
    struct sockaddr_in targets[3];
    int target_count = 0;

    if (strlen(punch->peer_public_ip) > 0 && punch->peer_public_port > 0) {
        memset(&targets[target_count], 0, sizeof(struct sockaddr_in));
        targets[target_count].sin_family = AF_INET;
        targets[target_count].sin_port = htons(punch->peer_public_port);
        inet_pton(AF_INET, punch->peer_public_ip, &targets[target_count].sin_addr);
        target_count++;
    }

    if (strlen(punch->peer_local_ip) > 0 && punch->peer_local_port > 0) {
        memset(&targets[target_count], 0, sizeof(struct sockaddr_in));
        targets[target_count].sin_family = AF_INET;
        targets[target_count].sin_port = htons(punch->peer_local_port);
        inet_pton(AF_INET, punch->peer_local_ip, &targets[target_count].sin_addr);
        target_count++;
    }

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

    // Punch loop
    uint8_t probe[] = "P2P";
    uint8_t recv_buf[64];

    uint64_t start = get_timestamp_ms();
    int attempt = 0;

    while ((get_timestamp_ms() - start) < PUNCH_TIMEOUT_MS &&
           attempt < PUNCH_MAX_ATTEMPTS * target_count) {

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
// PUNCH ORCHESTRATION
// ============================================

/*  Function: nat_punch_to_peer
    Description:
    Sends a MSG_NAT_PUNCH_REQ to the relay, asking it to coordinate
    a hole-punch with the target peer.

    Parameters:
    - mgr: NAT manager.
    - relay_socket_fd: Connected TCP socket to relay.
    - peer_id: Target peer's ID.
    - sender_id: Our client ID.

    Returns:
    - 0 on success, -1 on failure.
*/
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

    // Track the punch
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

/*  Function: nat_handle_punch_instruction
    Description:
    Executes the multi-strategy punch sequence when the relay tells us
    to connect to a specific peer.

    Parameters:
    - mgr: NAT manager.
    - instr: Punch instruction from relay with peer endpoints.

    Returns:
    - Connected TCP fd on success, -1 on failure (relay fallback needed).

    Strategies tried in order:
    1. Direct TCP to peer's LAN IP + P2P port
    2. TCP to peer's public IP + public port
    3. TCP to peer's public IP + P2P port
    4. UDP hole punch → TCP retry through punched hole
    5. Mark as RELAY_FALLBACK
*/
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

    if (!punch->is_initiator) {
        usleep(SIMULTANEOUS_DELAY_MS * 1000);
    }

    int connected_fd = -1;

    // Strategy 1: Direct LAN
    LOG_DEBUG("NAT: Trying direct TCP to %s:%u...",
              instr->peer_local_ip, instr->peer_p2p_port);
    connected_fd = nat_try_connect(instr->peer_local_ip, instr->peer_p2p_port, 0,
                                    PUNCH_CONNECT_TIMEOUT_MS);
    if (connected_fd >= 0) {
        LOG_INFO("NAT: Direct LAN connection succeeded!");
        punch->connected_fd = connected_fd;
        punch->state = PUNCH_STATE_CONNECTED;
        return connected_fd;
    }

    // Strategy 2: Public endpoint
    LOG_DEBUG("NAT: Trying TCP to public %s:%u...",
              instr->peer_public_ip, instr->peer_public_port);
    connected_fd = nat_try_connect(instr->peer_public_ip, instr->peer_public_port,
                                    mgr->local_nat.local_port, PUNCH_CONNECT_TIMEOUT_MS);
    if (connected_fd >= 0) {
        LOG_INFO("NAT: TCP punch through public endpoint succeeded!");
        punch->connected_fd = connected_fd;
        punch->state = PUNCH_STATE_CONNECTED;
        return connected_fd;
    }

    // Strategy 3: Public IP + P2P port
    if (instr->peer_p2p_port != instr->peer_public_port) {
        LOG_DEBUG("NAT: Trying TCP to %s:%u (public IP, P2P port)...",
                  instr->peer_public_ip, instr->peer_p2p_port);
        connected_fd = nat_try_connect(instr->peer_public_ip, instr->peer_p2p_port,
                                        mgr->local_nat.local_port, PUNCH_CONNECT_TIMEOUT_MS);
        if (connected_fd >= 0) {
            LOG_INFO("NAT: TCP to public IP P2P port succeeded!");
            punch->connected_fd = connected_fd;
            punch->state = PUNCH_STATE_CONNECTED;
            return connected_fd;
        }
    }

    // Strategy 4: UDP hole punch → TCP retry
    LOG_DEBUG("NAT: Attempting UDP hole punch...");
    int udp_result = nat_udp_hole_punch(mgr, punch);

    if (udp_result >= 0) {
        LOG_DEBUG("NAT: UDP hole created, retrying TCP...");
        connected_fd = nat_try_connect(instr->peer_public_ip, instr->peer_public_port,
                                        mgr->local_nat.local_port, PUNCH_CONNECT_TIMEOUT_MS);
        if (connected_fd >= 0) {
            LOG_INFO("NAT: TCP through UDP-punched hole succeeded!");
            punch->connected_fd = connected_fd;
            punch->state = PUNCH_STATE_CONNECTED;
            return connected_fd;
        }
    }

    // Strategy 5: Relay fallback
    LOG_WARN("NAT: All punch strategies failed, falling back to relay proxy");
    punch->state = PUNCH_STATE_RELAY_FALLBACK;

    return -1;
}