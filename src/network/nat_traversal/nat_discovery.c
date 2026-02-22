#define _POSIX_C_SOURCE 200809L
#include "nat_discovery.h"
#include "stun.h"
#include "../../common/logging.h"
#include "../../common/protocol.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*  Function: nat_get_local_ip
    Description:
    Discovers the local IP by creating a UDP socket and "connecting"
    to 8.8.8.8:53 (no actual traffic), then reading the bound address.

    Parameters:
    - ip: Output buffer for the IP string.
    - len: Buffer size.
*/
void nat_get_local_ip(char* ip, size_t len) {
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

/*  Function: nat_discover
    Description:
    Sends a MSG_NAT_DISCOVER to the relay server so it can tell us
    our public IP:port as seen from outside.

    Parameters:
    - mgr: NAT manager.
    - relay_socket_fd: Connected TCP socket to the relay.

    Returns:
    - 0 on success (response handled asynchronously), -1 on send failure.
*/
int nat_discover(nat_manager_t* mgr, int relay_socket_fd) {
    LOG_INFO("NAT: Sending discovery request to relay...");

    message_t msg;
    memset(&msg, 0, sizeof(msg));
    message_header_init(&msg.header, MSG_NAT_DISCOVER);

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

/*  Function: nat_stun_discover
    Description:
    Uses STUN to discover our public endpoint directly. Binds to the
    local P2P port so we learn the NAT mapping for that specific port.

    Parameters:
    - mgr: NAT manager (reads local_port, writes public_ip/port/nat_type).

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Creates a UDP socket bound to local P2P port.
    2. Calls stun_discover_multi (tries multiple STUN servers).
    3. Compares local vs public to heuristically determine NAT type.
*/
int nat_stun_discover(nat_manager_t* mgr) {
    LOG_INFO("NAT: Running STUN discovery...");

    int udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_fd < 0) {
        LOG_ERROR("NAT: Failed to create UDP socket for STUN");
        return -1;
    }

    int opt = 1;
    setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (mgr->local_nat.local_port > 0) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(mgr->local_nat.local_port);
        bind(udp_fd, (struct sockaddr*)&addr, sizeof(addr));
    }

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

/*  Function: nat_set_info
    Description:
    Sets NAT info from a relay-provided payload (MSG_NAT_INFO response).

    Parameters:
    - mgr: NAT manager.
    - info: The payload containing public_ip, public_port, nat_type.
*/
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