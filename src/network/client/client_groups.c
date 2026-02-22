#include "client_groups.h"
#include "client_messaging.h"
#include "../../common/logging.h"

#include <string.h>

int client_create_group(p2p_client_t* client, const char* group_name) {
    if (client->in_group) {
        LOG_WARN("Already in a group. Leave first.");
        return -1;
    }

    LOG_INFO("Creating group: %s", group_name);

    message_t msg;
    memset(&msg, 0, sizeof(msg));
    message_header_init(&msg.header, MSG_GROUP_CREATE);
    strncpy(msg.header.sender_id, client->id, MAX_ID_LENGTH - 1);

    payload_group_create_t* payload = (payload_group_create_t*)msg.payload;
    strncpy(payload->group_name, group_name, MAX_GROUP_NAME - 1);
    msg.header.payload_length = sizeof(payload_group_create_t);

    return client_send_message(client, &msg);
}

int client_join_group(p2p_client_t* client, const char* invite_token) {
    if (client->in_group) {
        LOG_WARN("Already in a group. Leave first.");
        return -1;
    }

    LOG_INFO("Joining group with token: %s", invite_token);

    message_t msg;
    memset(&msg, 0, sizeof(msg));
    message_header_init(&msg.header, MSG_GROUP_JOIN);
    strncpy(msg.header.sender_id, client->id, MAX_ID_LENGTH - 1);

    payload_group_join_t* payload = (payload_group_join_t*)msg.payload;
    strncpy(payload->invite_token, invite_token, INVITE_TOKEN_LENGTH - 1);
    msg.header.payload_length = sizeof(payload_group_join_t);

    return client_send_message(client, &msg);
}

int client_leave_group(p2p_client_t* client) {
    if (!client->in_group) {
        LOG_WARN("Not in a group.");
        return -1;
    }

    LOG_INFO("Leaving group: %s", client->group_id);

    message_t msg;
    memset(&msg, 0, sizeof(msg));
    message_header_init(&msg.header, MSG_GROUP_LEAVE);
    strncpy(msg.header.sender_id, client->id, MAX_ID_LENGTH - 1);

    payload_group_leave_t* payload = (payload_group_leave_t*)msg.payload;
    strncpy(payload->group_id, client->group_id, MAX_ID_LENGTH - 1);
    msg.header.payload_length = sizeof(payload_group_leave_t);

    int result = client_send_message(client, &msg);

    memset(client->group_id, 0, sizeof(client->group_id));
    memset(client->group_name, 0, sizeof(client->group_name));
    memset(client->invite_token, 0, sizeof(client->invite_token));
    client->in_group = false;

    return result;
}

int client_vote(p2p_client_t* client, bool approve) {
    if (!client->has_pending_vote) {
        LOG_WARN("No pending vote request.");
        return -1;
    }

    LOG_INFO("Voting %s for %s", approve ? "YES" : "NO",
             client->pending_vote_requester);

    message_t msg;
    memset(&msg, 0, sizeof(msg));
    message_header_init(&msg.header, MSG_GROUP_VOTE);
    strncpy(msg.header.sender_id, client->id, MAX_ID_LENGTH - 1);

    payload_group_vote_t* payload = (payload_group_vote_t*)msg.payload;
    strncpy(payload->group_id, client->pending_vote_group, MAX_ID_LENGTH - 1);
    strncpy(payload->request_id, client->pending_vote_request_id, MAX_ID_LENGTH - 1);
    strncpy(payload->requester_id, client->pending_vote_requester, MAX_ID_LENGTH - 1);
    payload->approved = approve ? 1 : 0;
    msg.header.payload_length = sizeof(payload_group_vote_t);

    client->has_pending_vote = false;
    memset(client->pending_vote_request_id, 0, sizeof(client->pending_vote_request_id));
    memset(client->pending_vote_requester, 0, sizeof(client->pending_vote_requester));
    memset(client->pending_vote_group, 0, sizeof(client->pending_vote_group));

    return client_send_message(client, &msg);
}

int client_request_invite(p2p_client_t* client) {
    if (!client->in_group) {
        LOG_WARN("Not in a group.");
        return -1;
    }

    LOG_INFO("Requesting new invite token");

    message_t msg;
    memset(&msg, 0, sizeof(msg));
    message_header_init(&msg.header, MSG_GROUP_INVITE);
    strncpy(msg.header.sender_id, client->id, MAX_ID_LENGTH - 1);

    payload_invite_request_t* payload = (payload_invite_request_t*)msg.payload;
    strncpy(payload->group_id, client->group_id, MAX_ID_LENGTH - 1);
    msg.header.payload_length = sizeof(payload_invite_request_t);

    return client_send_message(client, &msg);
}