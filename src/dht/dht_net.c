#define _POSIX_C_SOURCE 200809L
#include "dht_net.h"
#include "../common/logging.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

/*  Function: dht_net_open
    Description:
    Creates a UDP socket, sets SO_REUSEADDR, and binds to the given port on INADDR_ANY.

    Parameters:
    - ctx: DHT context. socket_fd is set on success.
    - port: UDP port to bind.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Creates a SOCK_DGRAM socket.
    2. Sets SO_REUSEADDR for quick restarts.
    3. Binds to INADDR_ANY:port.
    4. Stores the fd in ctx->socket_fd.
*/
int dht_net_open(dht_context_t* ctx, uint16_t port) {
    if (!ctx) return -1;

    ctx->socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx->socket_fd < 0) {
        LOG_ERROR("dht/net: Failed to create UDP socket: %s", strerror(errno));
        return -1;
    }

    int opt = 1;
    setsockopt(ctx->socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(port);
    bind_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(ctx->socket_fd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
        LOG_ERROR("dht/net: Failed to bind UDP port %d: %s", port, strerror(errno));
        close(ctx->socket_fd);
        ctx->socket_fd = -1;
        return -1;
    }

    return 0;
}

/*  Function: dht_net_close
    Description:
    Closes the UDP socket if open.

    Parameters:
    - ctx: DHT context.
*/
void dht_net_close(dht_context_t* ctx) {
    if (!ctx) return;
    if (ctx->socket_fd >= 0) {
        close(ctx->socket_fd);
        ctx->socket_fd = -1;
    }
}

/*  Function: dht_send_to
    Description:
    Sends a raw UDP datagram to the specified ip:port.

    Parameters:
    - ctx: DHT context (for socket_fd and stats).
    - data: Pointer to the message bytes.
    - len: Length in bytes.
    - ip: Destination IPv4 address string.
    - port: Destination port.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Builds sockaddr_in from ip and port.
    2. Calls sendto().
    3. Logs warnings on partial send.
    4. Increments ctx->messages_sent.
*/
int dht_send_to(dht_context_t* ctx, const void* data, size_t len,
                const char* ip, uint16_t port) {
    if (!ctx || !data || !ip || ctx->socket_fd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        LOG_ERROR("dht/net: Invalid IP address: %s", ip);
        return -1;
    }

    ssize_t sent = sendto(ctx->socket_fd, data, len, 0,
                           (struct sockaddr*)&addr, sizeof(addr));
    if (sent < 0) {
        LOG_ERROR("dht/net: sendto %s:%d failed: %s", ip, port, strerror(errno));
        return -1;
    }

    if ((size_t)sent != len) {
        LOG_WARN("dht/net: Partial send to %s:%d (%zd/%zu)", ip, port, sent, len);
    }

    ctx->messages_sent++;
    return 0;
}