#include "relay_handlers_file.h"
#include "relay_dispatch.h"
#include "../../common/logging.h"

#include <string.h>

int relay_handle_file_announce(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];
    payload_file_announce_t* announce = (payload_file_announce_t*)msg->payload;

    LOG_INFO("File announcement from %s: %s in group %s",
             msg->header.sender_id, announce->filename, announce->group_id);

    group_t* group = group_find_by_id(&server->group_mgr, announce->group_id);
    if (!group) {
        LOG_WARN("Group not found for file announcement");
        return -1;
    }

    for (int i = 0; i < group->member_count; i++) {
        if (strcmp(group->members[i].client_id, msg->header.sender_id) != 0) {
            int target_index = relay_find_client_index_by_id(server,
                                                             group->members[i].client_id);
            if (target_index >= 0) {
                relay_send_to_client(server, target_index, msg);
                LOG_DEBUG("Forwarded file announcement to %s",
                          group->members[i].client_id);
            }
        }
    }

    message_t ack;
    memset(&ack, 0, sizeof(ack));
    message_header_init(&ack.header, MSG_ACK);
    strncpy(ack.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(ack.header.target_id, client->id, MAX_ID_LENGTH - 1);
    return relay_send_to_client(server, client_index, &ack);
}

int relay_handle_file_list(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];
    payload_file_list_request_t* req = (payload_file_list_request_t*)msg->payload;

    LOG_INFO("File list request from %s for group %s",
             msg->header.sender_id, req->group_id);

    group_t* group = group_find_by_id(&server->group_mgr, req->group_id);
    if (!group) {
        LOG_WARN("Group not found for file list request");
        return -1;
    }

    for (int i = 0; i < group->member_count; i++) {
        if (strcmp(group->members[i].client_id, msg->header.sender_id) != 0) {
            int target_index = relay_find_client_index_by_id(server,
                                                             group->members[i].client_id);
            if (target_index >= 0) {
                relay_send_to_client(server, target_index, msg);
                LOG_DEBUG("Forwarded file list request to %s",
                          group->members[i].client_id);
            }
        }
    }

    message_t ack;
    memset(&ack, 0, sizeof(ack));
    message_header_init(&ack.header, MSG_ACK);
    strncpy(ack.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(ack.header.target_id, client->id, MAX_ID_LENGTH - 1);
    return relay_send_to_client(server, client_index, &ack);
}