#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "client_messaging.h"
#include "common/logging.h"
#include "core/group_mgmt/group_utils.h"

#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>

int client_send_message(p2p_client_t* client, message_t* msg) {
    if (!client->connected) {
        LOG_WARN("Cannot send message: not connected");
        return -1;
    }

    pthread_mutex_lock(&client->send_mutex);

    size_t total_size = message_total_size(msg);
    ssize_t sent = send(client->socket_fd, msg, total_size, 0);

    pthread_mutex_unlock(&client->send_mutex);

    if (sent < 0) {
        LOG_ERROR("Send failed: %s", strerror(errno));
        return -1;
    }

    client->bytes_sent += sent;
    client->messages_sent++;

    LOG_TRACE("Sent %zd bytes (%s)", sent, message_type_string(msg->header.type));
    return 0;
}

int client_send_ping(p2p_client_t* client) {
    message_t ping;
    memset(&ping, 0, sizeof(ping));
    message_header_init(&ping.header, MSG_PING);
    strncpy(ping.header.sender_id, client->id, MAX_ID_LENGTH - 1);

    payload_ping_t* payload = (payload_ping_t*)ping.payload;
    payload->ping_time = get_timestamp_ms();
    payload->ping_id = ++client->ping_counter;
    ping.header.payload_length = sizeof(payload_ping_t);

    client->last_ping_sent = payload->ping_time;

    LOG_DEBUG("Sending PING (id: %u)", payload->ping_id);
    return client_send_message(client, &ping);
}

void client_set_message_callback(p2p_client_t* client,
                                  message_callback_t callback, void* user_data) {
    client->on_message = callback;
    client->callback_user_data = user_data;
}