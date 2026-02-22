#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "client_nat.h"
#include "client_messaging.h"
#include "../nat_traversal/nat_traversal.h"
#include "common/logging.h"

#include <unistd.h>

#define PUNCH_CONNECT_TIMEOUT_MS 2000

int client_nat_discover(p2p_client_t* client) {
    if (!client->connected) {
        LOG_WARN("NAT: Not connected to relay");
        return -1;
    }
    return nat_discover(&client->nat_mgr, client->socket_fd);
}

int client_nat_punch(p2p_client_t* client, const char* peer_id) {
    if (!client->connected) {
        LOG_WARN("NAT: Not connected to relay");
        return -1;
    }
    return nat_punch_to_peer(&client->nat_mgr, client->socket_fd,
                              peer_id, client->id);
}

/*  Function: client_connect_to_peer
    Description:
    Multi-strategy connection to a peer:
    1. Check for existing NAT-punched connection.
    2. Try direct TCP.
    3. Initiate NAT punch via relay and wait up to 10s.

    Returns:
    - Connected fd, or -1 on failure.
*/
int client_connect_to_peer(p2p_client_t* client, const char* peer_id,
                           const char* peer_ip, uint16_t peer_port) {
    int existing_fd = nat_get_peer_connection(&client->nat_mgr, peer_id);
    if (existing_fd >= 0) {
        LOG_INFO("NAT: Reusing existing connection to %s (fd=%d)", peer_id, existing_fd);
        return existing_fd;
    }

    LOG_DEBUG("NAT: Trying direct connect to %s:%d...", peer_ip, peer_port);
    int fd = nat_try_connect(peer_ip, peer_port, 0, PUNCH_CONNECT_TIMEOUT_MS);

    if (fd >= 0) {
        LOG_INFO("NAT: Direct connection to %s:%d succeeded", peer_ip, peer_port);
        return fd;
    }

    LOG_INFO("NAT: Direct connection failed, initiating hole punch for %s...", peer_id);
    int punch_result = client_nat_punch(client, peer_id);

    if (punch_result >= 0) {
        for (int i = 0; i < 50; i++) {
            usleep(200 * 1000);
            fd = nat_get_peer_connection(&client->nat_mgr, peer_id);
            if (fd >= 0) {
                LOG_INFO("NAT: Hole punch succeeded for %s!", peer_id);
                return fd;
            }
        }
    }

    LOG_WARN("NAT: All connection methods failed for %s", peer_id);
    return -1;
}