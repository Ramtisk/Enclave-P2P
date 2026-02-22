#define _POSIX_C_SOURCE 200809L
#include "nat_traversal.h"
#include "nat_discovery.h"
#include "../../common/logging.h"

#include <string.h>
#include <unistd.h>
#include <pthread.h>

// ============================================
// STRING HELPERS (from nat_types.h)
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

/*  Function: nat_manager_init
    Description:
    Initializes the NAT manager: zeros state, discovers local IP,
    initializes punch slots and mutex.

    Parameters:
    - mgr: NAT manager to initialize.
    - relay_host: Relay server hostname/IP.
    - relay_port: Relay server port.

    Returns:
    - 0 on success.
*/
int nat_manager_init(nat_manager_t* mgr, const char* relay_host, uint16_t relay_port) {
    memset(mgr, 0, sizeof(nat_manager_t));

    strncpy(mgr->relay_host, relay_host, sizeof(mgr->relay_host) - 1);
    mgr->relay_port = relay_port;
    mgr->udp_punch_fd = -1;

    nat_get_local_ip(mgr->local_nat.local_ip, sizeof(mgr->local_nat.local_ip));

    pthread_mutex_init(&mgr->mutex, NULL);

    for (int i = 0; i < MAX_PUNCHES; i++) {
        mgr->punches[i].connected_fd = -1;
        mgr->punches[i].udp_fd = -1;
    }

    LOG_INFO("NAT manager initialized (local IP: %s)", mgr->local_nat.local_ip);
    return 0;
}

/*  Function: nat_manager_cleanup
    Description:
    Closes all punch connections, the shared UDP socket, and destroys the mutex.

    Parameters:
    - mgr: NAT manager to clean up.
*/
void nat_manager_cleanup(nat_manager_t* mgr) {
    pthread_mutex_lock(&mgr->mutex);

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
// PEER CONNECTION LOOKUP
// ============================================

/*  Function: nat_get_peer_connection
    Description:
    Searches punch contexts for an existing connected fd to the named peer.

    Parameters:
    - mgr: NAT manager.
    - peer_id: Peer to look up.

    Returns:
    - Connected fd, or -1 if no active connection exists.
*/
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