#define _POSIX_C_SOURCE 200809L
#include "client.h"
#include "client_recv.h"
#include "client_messaging.h"
#include "client_nat.h"
#include "../nat_traversal/nat_traversal.h"
#include "../../common/logging.h"
#include "../../common/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void generate_client_id(char* id, size_t len) {
    snprintf(id, len, "peer_%d_%lu", getpid(), get_timestamp_ms() % 100000);
}

int client_init(p2p_client_t* client, const char* relay_host, uint16_t relay_port) {
    memset(client, 0, sizeof(p2p_client_t));

    generate_client_id(client->id, sizeof(client->id));
    strncpy(client->relay_host, relay_host, sizeof(client->relay_host) - 1);
    client->relay_port = relay_port;
    client->socket_fd = -1;
    client->connected = false;
    client->in_group = false;
    client->has_pending_vote = false;

    pthread_mutex_init(&client->send_mutex, NULL);

    nat_manager_init(&client->nat_mgr, relay_host, relay_port);
    client->nat_mgr.local_nat.local_port = P2P_LISTEN_PORT_BASE + (getpid() % 1000);

    LOG_INFO("Client initialized: %s", client->id);
    return 0;
}

int client_connect(p2p_client_t* client) {
    LOG_INFO("Connecting to relay %s:%d...", client->relay_host, client->relay_port);

    client->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client->socket_fd < 0) {
        LOG_ERROR("Failed to create socket: %s", strerror(errno));
        return -1;
    }

    struct hostent* host = gethostbyname(client->relay_host);
    if (!host) {
        LOG_ERROR("Failed to resolve host: %s", client->relay_host);
        close(client->socket_fd);
        client->socket_fd = -1;
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(client->relay_port);
    memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);

    if (connect(client->socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("Failed to connect: %s", strerror(errno));
        close(client->socket_fd);
        client->socket_fd = -1;
        return -1;
    }

    client->connected = true;
    LOG_INFO("Connected to relay!");

    // Start receive thread
    client->recv_thread_running = true;
    if (pthread_create(&client->recv_thread, NULL, client_recv_thread, client) != 0) {
        LOG_ERROR("Failed to create receive thread");
        close(client->socket_fd);
        client->socket_fd = -1;
        client->connected = false;
        return -1;
    }

    // Start auto-ping thread
    client->ping_thread_running = true;
    if (pthread_create(&client->ping_thread, NULL, client_ping_thread, client) != 0) {
        LOG_ERROR("Failed to create ping thread");
        client->recv_thread_running = false;
        pthread_join(client->recv_thread, NULL);
        close(client->socket_fd);
        client->socket_fd = -1;
        client->connected = false;
        return -1;
    }

    // Send CONNECT message
    message_t connect_msg;
    memset(&connect_msg, 0, sizeof(connect_msg));
    message_header_init(&connect_msg.header, MSG_CONNECT);
    strncpy(connect_msg.header.sender_id, client->id, MAX_ID_LENGTH - 1);

    payload_connect_t* payload = (payload_connect_t*)connect_msg.payload;
    strncpy(payload->client_id, client->id, MAX_ID_LENGTH - 1);
    snprintf(payload->client_version, sizeof(payload->client_version),
             "%d.%d.%d", P2P_VERSION_MAJOR, P2P_VERSION_MINOR, P2P_VERSION_PATCH);
    payload->listen_port = 0;
    connect_msg.header.payload_length = sizeof(payload_connect_t);

    if (client_send_message(client, &connect_msg) != 0) {
        LOG_ERROR("Failed to send CONNECT message");
        client_disconnect(client);
        return -1;
    }

    client_nat_discover(client);

    LOG_INFO("CONNECT message sent");
    return 0;
}

void client_disconnect(p2p_client_t* client) {
    if (!client->connected) return;

    LOG_INFO("Disconnecting from relay...");

    if (client->in_group) {
        client_leave_group(client);
    }

    message_t disconnect_msg;
    memset(&disconnect_msg, 0, sizeof(disconnect_msg));
    message_header_init(&disconnect_msg.header, MSG_DISCONNECT);
    strncpy(disconnect_msg.header.sender_id, client->id, MAX_ID_LENGTH - 1);
    client_send_message(client, &disconnect_msg);

    client->recv_thread_running = false;
    client->ping_thread_running = false;
    client->connected = false;

    if (client->socket_fd > 0) {
        shutdown(client->socket_fd, SHUT_RDWR);
        close(client->socket_fd);
        client->socket_fd = -1;
    }

    pthread_join(client->recv_thread, NULL);
    pthread_join(client->ping_thread, NULL);

    LOG_INFO("Disconnected");
}

void client_cleanup(p2p_client_t* client) {
    if (client->connected) {
        client_disconnect(client);
    }

    nat_manager_cleanup(&client->nat_mgr);
    pthread_mutex_destroy(&client->send_mutex);

    LOG_INFO("Client cleanup complete");
    LOG_INFO("Statistics: %lu msgs sent, %lu msgs received, "
             "%lu bytes sent, %lu bytes received",
             client->messages_sent, client->messages_received,
             client->bytes_sent, client->bytes_received);
}

bool client_is_connected(p2p_client_t* client) {
    return client->connected;
}