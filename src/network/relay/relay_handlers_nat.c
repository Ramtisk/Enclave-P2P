#include "relay_handlers_nat.h"
#include "relay_dispatch.h"
#include "../nat_traversal/nat_types.h"
#include "../../common/logging.h"

#include <string.h>

int relay_handle_nat_discover(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];

    LOG_INFO("NAT: Discovery request from %s (public: %s:%d)",
             client->id, client->ip, client->port);

    message_t response;
    memset(&response, 0, sizeof(response));
    message_header_init(&response.header, MSG_NAT_INFO);
    strncpy(response.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(response.header.target_id, client->id, MAX_ID_LENGTH - 1);

    payload_nat_info_t* info = (payload_nat_info_t*)response.payload;
    strncpy(info->public_ip, client->ip, sizeof(info->public_ip) - 1);
    info->public_port = client->port;

    payload_punch_request_t* req = (payload_punch_request_t*)msg->payload;
    if (msg->header.payload_length >= sizeof(payload_punch_request_t)) {
        if (strcmp(req->local_ip, client->ip) == 0) {
            info->nat_type = NAT_TYPE_NONE;
        } else {
            info->nat_type = NAT_TYPE_RESTRICTED_CONE;
        }
    } else {
        info->nat_type = NAT_TYPE_UNKNOWN;
    }

    response.header.payload_length = sizeof(payload_nat_info_t);
    return relay_send_to_client(server, client_index, &response);
}

int relay_handle_nat_punch_req(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* requester = &server->clients[client_index];
    payload_punch_request_t* req = (payload_punch_request_t*)msg->payload;

    LOG_INFO("NAT: Punch request from %s → %s", requester->id, req->target_peer_id);

    int target_idx = relay_find_client_index_by_id(server, req->target_peer_id);
    if (target_idx < 0) {
        LOG_WARN("NAT: Target peer %s not found", req->target_peer_id);
        message_t nack;
        memset(&nack, 0, sizeof(nack));
        message_header_init(&nack.header, MSG_NACK);
        strncpy(nack.header.sender_id, "relay", MAX_ID_LENGTH - 1);
        nack.header.payload_length = 0;
        return relay_send_to_client(server, client_index, &nack);
    }

    client_connection_t* target = &server->clients[target_idx];

    // Instruction for requester (initiator)
    message_t instr_a;
    memset(&instr_a, 0, sizeof(instr_a));
    message_header_init(&instr_a.header, MSG_NAT_PUNCH_INSTR);
    strncpy(instr_a.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(instr_a.header.target_id, requester->id, MAX_ID_LENGTH - 1);

    payload_punch_instruction_t* pi_a = (payload_punch_instruction_t*)instr_a.payload;
    strncpy(pi_a->peer_id, target->id, sizeof(pi_a->peer_id) - 1);
    strncpy(pi_a->peer_public_ip, target->ip, sizeof(pi_a->peer_public_ip) - 1);
    pi_a->peer_public_port = target->port;
    strncpy(pi_a->peer_local_ip, req->local_ip, sizeof(pi_a->peer_local_ip) - 1);
    pi_a->peer_local_port = req->local_port;
    pi_a->peer_p2p_port = req->p2p_listen_port;
    pi_a->you_are_initiator = 1;
    instr_a.header.payload_length = sizeof(payload_punch_instruction_t);

    relay_send_to_client(server, client_index, &instr_a);

    // Instruction for target (responder)
    message_t instr_b;
    memset(&instr_b, 0, sizeof(instr_b));
    message_header_init(&instr_b.header, MSG_NAT_PUNCH_INSTR);
    strncpy(instr_b.header.sender_id, "relay", MAX_ID_LENGTH - 1);
    strncpy(instr_b.header.target_id, target->id, MAX_ID_LENGTH - 1);

    payload_punch_instruction_t* pi_b = (payload_punch_instruction_t*)instr_b.payload;
    strncpy(pi_b->peer_id, requester->id, sizeof(pi_b->peer_id) - 1);
    strncpy(pi_b->peer_public_ip, requester->ip, sizeof(pi_b->peer_public_ip) - 1);
    pi_b->peer_public_port = requester->port;
    strncpy(pi_b->peer_local_ip, req->local_ip, sizeof(pi_b->peer_local_ip) - 1);
    pi_b->peer_local_port = req->local_port;
    pi_b->peer_p2p_port = req->p2p_listen_port;
    pi_b->you_are_initiator = 0;
    instr_b.header.payload_length = sizeof(payload_punch_instruction_t);

    relay_send_to_client(server, target_idx, &instr_b);

    LOG_INFO("NAT: Punch instructions sent to both peers");
    return 0;
}

int relay_handle_nat_punch_result(relay_server_t* server, int client_index, message_t* msg) {
    client_connection_t* client = &server->clients[client_index];
    payload_punch_result_t* result = (payload_punch_result_t*)msg->payload;

    LOG_INFO("NAT: Punch result from %s → %s: %s",
             client->id, result->peer_id,
             result->success ? "SUCCESS" : "FAILED (need relay)");

    return 0;
}

int relay_handle_nat_relay_data(relay_server_t* server, int client_index, message_t* msg) {
    (void)client_index;
    payload_relay_proxy_t* proxy = (payload_relay_proxy_t*)msg->payload;

    int target_idx = relay_find_client_index_by_id(server, proxy->target_peer_id);
    if (target_idx < 0) {
        LOG_WARN("NAT: Relay proxy target %s not found", proxy->target_peer_id);
        return -1;
    }

    strncpy(msg->header.target_id, proxy->target_peer_id, MAX_ID_LENGTH - 1);
    relay_send_to_client(server, target_idx, msg);

    LOG_TRACE("NAT: Proxied %u bytes to %s", proxy->data_length, proxy->target_peer_id);
    return 0;
}