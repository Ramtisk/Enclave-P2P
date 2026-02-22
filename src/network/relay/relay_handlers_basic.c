
#include "relay_dispatch.h"
#include "common/logging.h"

#include <string.h>
#include <time.h>
#include <unistd.h>

// Forward declaration (defined in relay.c)
void relay_disconnect_client(relay_server_t* server, int client_index);

int relay_handle_ping(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];
    client->last_ping = get_timestamp_ms();

    message_t pong;
    memset(&pong, 0, sizeof(pong));
    message_header_init(&pong.header, MSG_PONG);
    strncpy(pong.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(pong.header.target_id, client->id, MAX_ID_LENGTH - 1);

    payload_ping_t* ping_payload = (payload_ping_t*)msg->payload;
    payload_ping_t* pong_payload = (payload_ping_t*)pong.payload;
    pong_payload->ping_time = ping_payload->ping_time;
    pong_payload->ping_id = ping_payload->ping_id;
    pong.header.payload_length = sizeof(payload_ping_t);

    LOG_DEBUG("PING from %s (id: %u), sending PONG",
              client->id, ping_payload->ping_id);

    return relay_send_to_client(server, client_index, &pong);
}

int relay_handle_connect(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];
    payload_connect_t* payload = (payload_connect_t*)msg->payload;

    if (strlen(payload->client_id) > 0) {
        strncpy(client->id, payload->client_id, MAX_ID_LENGTH - 1);
    }

    client->authenticated = true;
    client->last_ping = get_timestamp_ms();

    LOG_INFO("Client %s authenticated (version: %s, listen_port: %d)",
             client->id, payload->client_version, payload->listen_port);

    message_t ack;
    memset(&ack, 0, sizeof(ack));
    message_header_init(&ack.header, MSG_ACK);
    strncpy(ack.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(ack.header.target_id, client->id, MAX_ID_LENGTH - 1);

    return relay_send_to_client(server, client_index, &ack);
}

int relay_handle_disconnect(relay_server_t* server, int client_index, message_t* msg) {
    (void)msg;
    relay_disconnect_client(server, client_index);
    return 0;
}