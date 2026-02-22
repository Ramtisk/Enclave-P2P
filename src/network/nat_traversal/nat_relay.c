#include "nat_relay.h"
#include "../../common/logging.h"
#include "../../common/protocol.h"

#include <string.h>
#include <sys/socket.h>

/*  Function: nat_relay_send
    Description:
    Wraps data in a MSG_NAT_RELAY_DATA message and sends it to the relay,
    which forwards it to the target peer.

    Parameters:
    - mgr: NAT manager (unused, reserved for future relay session state).
    - relay_fd: Connected TCP socket to the relay.
    - peer_id: Destination peer's ID.
    - data: Payload bytes.
    - len: Payload length.

    Returns:
    - 0 on success, -1 on failure.
*/
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