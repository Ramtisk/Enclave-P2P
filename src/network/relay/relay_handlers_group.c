#include "relay_handlers_group.h"
#include "relay_dispatch.h"
#include "../../common/logging.h"

#include <string.h>

// Forward declaration
void relay_disconnect_client(relay_server_t* server, int client_index);

int relay_handle_group_create(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];
    payload_group_create_t* payload = (payload_group_create_t*)msg->payload;

    LOG_INFO("Client %s creating group: %s", client->id, payload->group_name);

    group_t* group = group_create(&server->group_mgr, payload->group_name,
                                  client->id, client->ip, client->port);
    if (!group) {
        message_t nack;
        memset(&nack, 0, sizeof(nack));
        message_header_init(&nack.header, MSG_NACK);
        strncpy(nack.header.sender_id, "relay", MAX_ID_LENGTH - 1);
        strncpy(nack.header.target_id, client->id, MAX_ID_LENGTH - 1);
        return relay_send_to_client(server, client_index, &nack);
    }

    strncpy(client->group_id, group->group_id, MAX_ID_LENGTH - 1);

    message_t ack;
    memset(&ack, 0, sizeof(ack));
    message_header_init(&ack.header, MSG_ACK);
    strncpy(ack.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(ack.header.target_id, client->id, MAX_ID_LENGTH - 1);

    payload_group_created_t* response = (payload_group_created_t*)ack.payload;
    strncpy(response->group_id, group->group_id, MAX_ID_LENGTH - 1);
    strncpy(response->invite_token, group->invite_token, INVITE_TOKEN_LENGTH - 1);
    ack.header.payload_length = sizeof(payload_group_created_t);

    LOG_INFO("Group created: %s (token: %s)", group->group_id, group->invite_token);
    return relay_send_to_client(server, client_index, &ack);
}

int relay_handle_group_join(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];
    payload_group_join_t* payload = (payload_group_join_t*)msg->payload;

    LOG_INFO("Client %s attempting to join with token: %s",
             client->id, payload->invite_token);

    group_t* group = group_find_by_token(&server->group_mgr, payload->invite_token);
    if (!group) {
        LOG_WARN("Invalid invite token: %s", payload->invite_token);
        message_t reject;
        memset(&reject, 0, sizeof(reject));
        message_header_init(&reject.header, MSG_GROUP_REJECTED);
        strncpy(reject.header.sender_id, "relay", MAX_ID_LENGTH - 1);
        strncpy(reject.header.target_id, client->id, MAX_ID_LENGTH - 1);
        return relay_send_to_client(server, client_index, &reject);
    }

    if (group_is_member(group, client->id)) {
        LOG_WARN("Client %s already in group %s", client->id, group->group_id);
        message_t nack;
        memset(&nack, 0, sizeof(nack));
        message_header_init(&nack.header, MSG_NACK);
        strncpy(nack.header.sender_id, "relay", MAX_ID_LENGTH - 1);
        strncpy(nack.header.target_id, client->id, MAX_ID_LENGTH - 1);
        return relay_send_to_client(server, client_index, &nack);
    }

    pending_join_t* pending = group_create_join_request(group, client->id,
                                                        client->ip, client->port);
    if (!pending) {
        message_t nack;
        memset(&nack, 0, sizeof(nack));
        message_header_init(&nack.header, MSG_NACK);
        strncpy(nack.header.sender_id, "relay", MAX_ID_LENGTH - 1);
        strncpy(nack.header.target_id, client->id, MAX_ID_LENGTH - 1);
        return relay_send_to_client(server, client_index, &nack);
    }

    relay_send_vote_request_to_members(server, group, pending);

    message_t ack;
    memset(&ack, 0, sizeof(ack));
    message_header_init(&ack.header, MSG_ACK);
    strncpy(ack.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(ack.header.target_id, client->id, MAX_ID_LENGTH - 1);

    LOG_INFO("Join request created, waiting for %d votes", pending->votes_needed);
    return relay_send_to_client(server, client_index, &ack);
}

int relay_handle_group_vote(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];
    payload_group_vote_t* payload = (payload_group_vote_t*)msg->payload;

    LOG_INFO("Vote from %s: %s for request %s",
             client->id, payload->approved ? "YES" : "NO", payload->request_id);

    group_t* group = group_find_by_id(&server->group_mgr, payload->group_id);
    if (!group) {
        LOG_WARN("Group not found: %s", payload->group_id);
        return -1;
    }

    int result = group_register_vote(group, payload->request_id,
                                     client->id, payload->approved);
    if (result < 0) {
        LOG_WARN("Failed to register vote: %d", result);
        return result;
    }

    int vote_result = group_check_vote_result(group, payload->request_id);
    if (vote_result == 0) return 0;  // Voting still in progress

    pending_join_t* pending = group_find_pending_join(group, payload->request_id);
    if (!pending) return -1;

    int requester_index = relay_find_client_index_by_id(server, pending->requester_id);

    if (vote_result == 1) {
        LOG_INFO("Join request %s APPROVED for %s",
                 payload->request_id, pending->requester_id);

        group_add_member(group, pending->requester_id,
                         pending->requester_ip, pending->requester_port, false);

        if (requester_index >= 0) {
            strncpy(server->clients[requester_index].group_id,
                    group->group_id, MAX_ID_LENGTH - 1);

            message_t approved;
            memset(&approved, 0, sizeof(approved));
            message_header_init(&approved.header, MSG_GROUP_APPROVED);
            strncpy(approved.header.sender_id, "relay", MAX_ID_LENGTH - 1);
            strncpy(approved.header.target_id, pending->requester_id, MAX_ID_LENGTH - 1);

            payload_group_result_t* res = (payload_group_result_t*)approved.payload;
            strncpy(res->group_id, group->group_id, MAX_ID_LENGTH - 1);
            strncpy(res->group_name, group->group_name, MAX_GROUP_NAME - 1);
            res->member_count = group->member_count;
            approved.header.payload_length = sizeof(payload_group_result_t);

            relay_send_to_client(server, requester_index, &approved);
            relay_send_group_info(server, requester_index, group);
        }

        group_regenerate_token(group);
    } else {
        LOG_INFO("Join request %s REJECTED for %s",
                 payload->request_id, pending->requester_id);

        if (requester_index >= 0) {
            message_t rejected;
            memset(&rejected, 0, sizeof(rejected));
            message_header_init(&rejected.header, MSG_GROUP_REJECTED);
            strncpy(rejected.header.sender_id, "relay", MAX_ID_LENGTH - 1);
            strncpy(rejected.header.target_id, pending->requester_id, MAX_ID_LENGTH - 1);

            payload_group_result_t* res = (payload_group_result_t*)rejected.payload;
            strncpy(res->group_id, group->group_id, MAX_ID_LENGTH - 1);
            rejected.header.payload_length = sizeof(payload_group_result_t);

            relay_send_to_client(server, requester_index, &rejected);
        }
    }

    group_cleanup_pending(group, payload->request_id);
    return 0;
}

int relay_handle_group_leave(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];
    payload_group_leave_t* payload = (payload_group_leave_t*)msg->payload;

    LOG_INFO("Client %s leaving group %s", client->id, payload->group_id);

    group_t* group = group_find_by_id(&server->group_mgr, payload->group_id);
    if (!group) return -1;

    group_remove_member(group, client->id);
    memset(client->group_id, 0, sizeof(client->group_id));

    if (group->member_count == 0) {
        LOG_INFO("Group %s empty, destroying", group->group_id);
        group_destroy(&server->group_mgr, payload->group_id);
    }

    message_t ack;
    memset(&ack, 0, sizeof(ack));
    message_header_init(&ack.header, MSG_ACK);
    strncpy(ack.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(ack.header.target_id, client->id, MAX_ID_LENGTH - 1);

    return relay_send_to_client(server, client_index, &ack);
}

int relay_handle_group_invite(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];
    payload_invite_request_t* payload = (payload_invite_request_t*)msg->payload;

    LOG_INFO("Client %s requesting invite for group %s",
             client->id, payload->group_id);

    group_t* group = group_find_by_id(&server->group_mgr, payload->group_id);
    if (!group || !group_is_member(group, client->id)) {
        message_t nack;
        memset(&nack, 0, sizeof(nack));
        message_header_init(&nack.header, MSG_NACK);
        strncpy(nack.header.sender_id, "relay", MAX_ID_LENGTH - 1);
        strncpy(nack.header.target_id, client->id, MAX_ID_LENGTH - 1);
        return relay_send_to_client(server, client_index, &nack);
    }

    group_regenerate_token(group);

    message_t response;
    memset(&response, 0, sizeof(response));
    message_header_init(&response.header, MSG_ACK);
    strncpy(response.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(response.header.target_id, client->id, MAX_ID_LENGTH - 1);

    payload_invite_response_t* resp = (payload_invite_response_t*)response.payload;
    strncpy(resp->group_id, group->group_id, MAX_ID_LENGTH - 1);
    strncpy(resp->invite_token, group->invite_token, INVITE_TOKEN_LENGTH - 1);
    response.header.payload_length = sizeof(payload_invite_response_t);

    return relay_send_to_client(server, client_index, &response);
}

// ============================================
// GROUP UTILITIES
// ============================================

int relay_send_vote_request_to_members(relay_server_t* server, group_t* group,
                                       pending_join_t* pending) {
    int sent = 0;
    for (int i = 0; i < group->member_count; i++) {
        int ci = relay_find_client_index_by_id(server, group->members[i].client_id);
        if (ci < 0) continue;

        message_t vote_req;
        memset(&vote_req, 0, sizeof(vote_req));
        message_header_init(&vote_req.header, MSG_GROUP_VOTE_REQ);
        strncpy(vote_req.header.sender_id, "relay", MAX_ID_LENGTH - 1);
        strncpy(vote_req.header.target_id, group->members[i].client_id, MAX_ID_LENGTH - 1);

        payload_vote_request_t* payload = (payload_vote_request_t*)vote_req.payload;
        strncpy(payload->group_id, group->group_id, MAX_ID_LENGTH - 1);
        strncpy(payload->requester_id, pending->requester_id, MAX_ID_LENGTH - 1);
        strncpy(payload->request_id, pending->request_id, MAX_ID_LENGTH - 1);
        vote_req.header.payload_length = sizeof(payload_vote_request_t);

        if (relay_send_to_client(server, ci, &vote_req) == 0) sent++;
    }

    LOG_INFO("Sent vote request to %d members", sent);
    return sent;
}

int relay_send_group_info(relay_server_t* server, int client_index, group_t* group) {
    message_t info;
    memset(&info, 0, sizeof(info));
    message_header_init(&info.header, MSG_GROUP_INFO);
    strncpy(info.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(info.header.target_id, server->clients[client_index].id, MAX_ID_LENGTH - 1);

    payload_group_info_t* payload = (payload_group_info_t*)info.payload;
    strncpy(payload->group_id, group->group_id, MAX_ID_LENGTH - 1);
    payload->peer_count = group->member_count;

    for (int i = 0; i < group->member_count && i < MAX_GROUP_MEMBERS; i++) {
        strncpy(payload->peers[i].id, group->members[i].client_id, MAX_ID_LENGTH - 1);
        strncpy(payload->peers[i].ip, group->members[i].ip, sizeof(payload->peers[i].ip) - 1);
        payload->peers[i].port = group->members[i].port;
    }

    info.header.payload_length = sizeof(payload_group_info_t);

    LOG_INFO("Sending group info to %s (%d peers)",
             server->clients[client_index].id, payload->peer_count);
    return relay_send_to_client(server, client_index, &info);
}