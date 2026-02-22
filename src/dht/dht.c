#define _POSIX_C_SOURCE 200809L
#include "dht.h"
#include "dht_net.h"
#include "dht_handlers.h"
#include "dht_maintenance.h"
#include "dht_pending.h"
#include "dht_lookup.h"
#include "../common/logging.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <poll.h>

// ============================================
// LISTENER THREAD
// ============================================

/*  Function: dht_listen_thread
    Description:
    Receives UDP datagrams and dispatches them via dht_handle_message.

    Steps:
    1. Polls the socket with a 1-second timeout.
    2. On data available, calls recvfrom.
    3. Extracts sender IP/port and calls dht_handle_message.
    4. Repeats until ctx->running is false.
*/
static void* dht_listen_thread(void* arg) {
    dht_context_t* ctx = (dht_context_t*)arg;

    LOG_INFO("dht: Listener started on UDP port %d", ctx->listen_port);

    uint8_t buf[65536];
    struct sockaddr_in from_addr;
    socklen_t from_len;

    while (ctx->running) {
        struct pollfd pfd;
        pfd.fd = ctx->socket_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        int ret = poll(&pfd, 1, 1000);

        if (ret < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("dht: poll() failed: %s", strerror(errno));
            break;
        }

        if (ret == 0) continue;
        if (!(pfd.revents & POLLIN)) continue;

        from_len = sizeof(from_addr);
        ssize_t received = recvfrom(ctx->socket_fd, buf, sizeof(buf), 0,
                                     (struct sockaddr*)&from_addr, &from_len);

        if (received < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            LOG_ERROR("dht: recvfrom failed: %s", strerror(errno));
            continue;
        }

        if (received == 0) continue;

        char from_ip[46];
        inet_ntop(AF_INET, &from_addr.sin_addr, from_ip, sizeof(from_ip));
        uint16_t from_port = ntohs(from_addr.sin_port);

        dht_handle_message(ctx, buf, (size_t)received, from_ip, from_port);
    }

    LOG_INFO("dht: Listener stopped");
    return NULL;
}

// ============================================
// LIFECYCLE
// ============================================

/*  Function: dht_init
    Description:
    Initializes the DHT with a randomly generated node ID.

    Parameters:
    - ctx: DHT context to initialize.
    - port: UDP port to bind.

    Returns:
    - 0 on success, -1 on failure.
*/
int dht_init(dht_context_t* ctx, uint16_t port) {
    dht_node_id_t id;
    dht_id_random(&id);
    return dht_init_with_id(ctx, &id, port);
}

/*  Function: dht_init_with_id
    Description:
    Initializes all DHT subsystems: routing table, storage, UDP socket, mutexes.

    Parameters:
    - ctx: DHT context.
    - id: Node ID to use.
    - port: UDP port.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Zeros the context.
    2. Initializes routing table with the given ID.
    3. Initializes storage.
    4. Sets listen_ip/port, initializes mutexes.
    5. Opens and binds the UDP socket via dht_net_open.
    6. Logs the node ID prefix and port.
*/
int dht_init_with_id(dht_context_t* ctx, const dht_node_id_t* id, uint16_t port) {
    if (!ctx || !id) return -1;

    memset(ctx, 0, sizeof(dht_context_t));

    if (routing_table_init(&ctx->routing_table, id) != 0) {
        LOG_ERROR("dht: Failed to init routing table");
        return -1;
    }

    if (dht_storage_init(&ctx->storage) != 0) {
        routing_table_cleanup(&ctx->routing_table);
        LOG_ERROR("dht: Failed to init storage");
        return -1;
    }

    ctx->listen_port = port;
    strncpy(ctx->listen_ip, "0.0.0.0", sizeof(ctx->listen_ip) - 1);
    ctx->socket_fd = -1;
    ctx->next_transaction_id = 1;

    pthread_mutex_init(&ctx->mutex, NULL);
    pthread_mutex_init(&ctx->pending_mutex, NULL);

    if (dht_net_open(ctx, port) != 0) {
        dht_cleanup(ctx);
        return -1;
    }

    char hex[DHT_ID_BYTES * 2 + 1];
    dht_id_to_hex(id, hex, sizeof(hex));
    LOG_INFO("dht: Initialized on UDP port %d (node_id=%.16s...)", port, hex);

    return 0;
}

/*  Function: dht_start
    Description:
    Starts the listener and maintenance background threads.

    Parameters:
    - ctx: DHT context (must be initialized).

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Sets ctx->running = true.
    2. Creates the listener thread (dht_listen_thread).
    3. Creates the maintenance thread (dht_maintenance_thread).
    4. On failure, joins any already-started threads.
*/
int dht_start(dht_context_t* ctx) {
    if (!ctx) return -1;
    if (ctx->running) {
        LOG_WARN("dht: Already running");
        return 0;
    }

    ctx->running = true;

    if (pthread_create(&ctx->listen_thread, NULL, dht_listen_thread, ctx) != 0) {
        LOG_ERROR("dht: Failed to start listener thread: %s", strerror(errno));
        ctx->running = false;
        return -1;
    }

    if (pthread_create(&ctx->maintenance_thread, NULL,
                        dht_maintenance_thread, ctx) != 0) {
        LOG_ERROR("dht: Failed to start maintenance thread: %s", strerror(errno));
        ctx->running = false;
        pthread_join(ctx->listen_thread, NULL);
        return -1;
    }

    LOG_INFO("dht: Started (UDP port %d, 2 threads)", ctx->listen_port);
    return 0;
}

/*  Function: dht_stop
    Description:
    Signals both threads to exit and joins them.

    Parameters:
    - ctx: DHT context.

    Steps:
    1. Sets ctx->running = false.
    2. Joins listener and maintenance threads (max 1s wait from poll timeout).
    3. Logs final stats.
*/
void dht_stop(dht_context_t* ctx) {
    if (!ctx || !ctx->running) return;

    LOG_INFO("dht: Stopping...");
    ctx->running = false;

    pthread_join(ctx->listen_thread, NULL);
    pthread_join(ctx->maintenance_thread, NULL);

    LOG_INFO("dht: Stopped (sent=%lu, recv=%lu, lookups=%lu, timeouts=%lu)",
             (unsigned long)ctx->messages_sent,
             (unsigned long)ctx->messages_received,
             (unsigned long)ctx->lookups_completed,
             (unsigned long)ctx->timeouts);
}

/*  Function: dht_cleanup
    Description:
    Stops threads (if running), closes the socket, cleans up routing table,
    storage, and mutexes.

    Parameters:
    - ctx: DHT context.
*/
void dht_cleanup(dht_context_t* ctx) {
    if (!ctx) return;

    if (ctx->running) {
        dht_stop(ctx);
    }

    dht_net_close(ctx);
    routing_table_cleanup(&ctx->routing_table);
    dht_storage_cleanup(&ctx->storage);
    pthread_mutex_destroy(&ctx->mutex);
    pthread_mutex_destroy(&ctx->pending_mutex);

    LOG_DEBUG("dht: Cleaned up all resources");
}

// ============================================
// BOOTSTRAP
// ============================================

/*  Function: dht_add_bootstrap
    Description:
    Adds a known bootstrap node to the list (max 16).

    Parameters:
    - ctx: DHT context.
    - ip: Bootstrap node IP.
    - port: Bootstrap node port.

    Returns:
    - 0 on success, -1 if list is full.
*/
int dht_add_bootstrap(dht_context_t* ctx, const char* ip, uint16_t port) {
    if (!ctx || !ip) return -1;
    if (ctx->bootstrap_count >= 16) {
        LOG_WARN("dht: Bootstrap list full (max 16)");
        return -1;
    }

    int idx = ctx->bootstrap_count++;
    strncpy(ctx->bootstrap_nodes[idx].ip, ip,
            sizeof(ctx->bootstrap_nodes[idx].ip) - 1);
    ctx->bootstrap_nodes[idx].port = port;

    LOG_DEBUG("dht: Added bootstrap node %s:%d", ip, port);
    return 0;
}

/*  Function: dht_bootstrap
    Description:
    Bootstraps into the DHT network by pinging known nodes and performing
    a self-lookup to populate the routing table.

    Parameters:
    - ctx: DHT context.

    Returns:
    - 0 if at least one node was discovered, -1 otherwise.

    Steps:
    1. Pings all bootstrap nodes.
    2. Waits 500ms for pongs.
    3. Performs FIND_NODE(self_id) to discover nearby nodes.
    4. Logs the number of discovered nodes.
*/
int dht_bootstrap(dht_context_t* ctx) {
    if (!ctx) return -1;

    if (ctx->bootstrap_count == 0) {
        LOG_WARN("dht: No bootstrap nodes configured");
        return -1;
    }

    LOG_INFO("dht: Bootstrapping with %d known nodes...", ctx->bootstrap_count);

    for (int i = 0; i < ctx->bootstrap_count; i++) {
        LOG_DEBUG("dht: Pinging bootstrap %s:%d",
                  ctx->bootstrap_nodes[i].ip, ctx->bootstrap_nodes[i].port);
        dht_ping(ctx, ctx->bootstrap_nodes[i].ip, ctx->bootstrap_nodes[i].port);
    }

    usleep(500000); // 500ms

    dht_node_t results[DHT_K_BUCKET_SIZE];
    int found = dht_find_node(ctx, &ctx->routing_table.self_id,
                               results, DHT_K_BUCKET_SIZE);

    int total, good, used;
    routing_table_stats(&ctx->routing_table, &total, &good, &used);

    LOG_INFO("dht: Bootstrap complete — %d nodes discovered (%d good, %d buckets, "
             "self-lookup returned %d)",
             total, good, used, found);

    return total > 0 ? 0 : -1;
}