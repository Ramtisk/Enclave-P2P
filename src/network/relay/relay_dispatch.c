#include "relay_dispatch.h"
#include "relay_handlers_basic.h"
#include "relay_handlers_group.h"
#include "relay_handlers_file.h"
#include "relay_handlers_nat.h"
#include "../../common/logging.h"

#include <string.h>
#include <errno.h>
#include <sys/socket.h>

int relay_process_message(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];

    LOG_DEBUG("Message type %s from client %s",
              message_type_string(msg->header.type), client->id);

    switch (msg->header.type) {
        case MSG_PING:       return relay_handle_ping(server, client_index, msg);
        case MSG_CONNECT:    return relay_handle_connect(server, client_index, msg);
        case MSG_DISCONNECT: return relay_handle_disconnect(server, client_index, msg);

        case MSG_GROUP_CREATE: return relay_handle_group_create(server, client_index, msg);
        case MSG_GROUP_JOIN:   return relay_handle_group_join(server, client_index, msg);
        case MSG_GROUP_VOTE:   return relay_handle_group_vote(server, client_index, msg);
        case MSG_GROUP_LEAVE:  return relay_handle_group_leave(server, client_index, msg);
        case MSG_GROUP_INVITE: return relay_handle_group_invite(server, client_index, msg);

        case MSG_FILE_ANNOUNCE: return relay_handle_file_announce(server, client_index, msg);
        case MSG_FILE_LIST:     return relay_handle_file_list(server, client_index, msg);

        case MSG_NAT_DISCOVER:     return relay_handle_nat_discover(server, client_index, msg);
        case MSG_NAT_PUNCH_REQ:    return relay_handle_nat_punch_req(server, client_index, msg);
        case MSG_NAT_PUNCH_RESULT: return relay_handle_nat_punch_result(server, client_index, msg);
        case MSG_NAT_RELAY_DATA:   return relay_handle_nat_relay_data(server, client_index, msg);

        default:
            LOG_WARN("Unknown message type: %d", msg->header.type);
            return -1;
    }
}

int relay_send_to_client(relay_server_t* server, int client_index, message_t* msg) {
    if (client_index < 0 || client_index >= MAX_CLIENTS) return -1;

    client_connection_t* client = &server->clients[client_index];
    if (client->socket_fd <= 0) return -1;

    size_t total_size = message_total_size(msg);
    ssize_t sent = send(client->socket_fd, msg, total_size, 0);

    if (sent < 0) {
        LOG_ERROR("Error sending to client %s: %s", client->id, strerror(errno));
        return -1;
    }

    server->total_bytes_sent += sent;
    LOG_TRACE("Sent %zd bytes to %s", sent, client->id);
    return 0;
}

int relay_broadcast(relay_server_t* server, message_t* msg, int exclude_index) {
    int count = 0;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (i != exclude_index && server->clients[i].socket_fd > 0) {
            if (relay_send_to_client(server, i, msg) == 0) count++;
        }
    }
    LOG_DEBUG("Broadcast to %d clients", count);
    return count;
}

client_connection_t* relay_find_client_by_id(relay_server_t* server, const char* id) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (server->clients[i].socket_fd > 0 &&
            strcmp(server->clients[i].id, id) == 0) {
            return &server->clients[i];
        }
    }
    return NULL;
}

int relay_find_client_index_by_id(relay_server_t* server, const char* id) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (server->clients[i].socket_fd > 0 &&
            strcmp(server->clients[i].id, id) == 0) {
            return i;
        }
    }
    return -1;
}