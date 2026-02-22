#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "client_recv.h"
#include "client_messaging.h"
#include "client_files.h"
#include "client_nat.h"
#include "../nat_traversal/nat_traversal.h"
#include "common/logging.h"
#include "common/config.h"
#include "core/group_mgmt/group_utils.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>

/*  Function: client_recv_thread
    Description:
    Reads messages from the relay socket and dispatches them:
    - PONG: updates RTT
    - GROUP_VOTE_REQ: stores pending vote
    - GROUP_APPROVED/REJECTED: updates group state
    - GROUP_INFO: logs peer list
    - FILE_ANNOUNCE: registers remote file
    - FILE_LIST: responds with our files
    - NAT_INFO: updates NAT discovery
    - NAT_PUNCH_INSTR: runs punch + reports result
    - All others: forwarded to user callback
*/
void* client_recv_thread(void* arg) {
    p2p_client_t* client = (p2p_client_t*)arg;
    uint8_t buffer[READ_BUFFER_SIZE];

    LOG_DEBUG("Receive thread started");

    while (client->recv_thread_running && client->connected) {
        ssize_t bytes = recv(client->socket_fd, buffer, sizeof(buffer), 0);

        if (bytes <= 0) {
            if (bytes == 0) {
                LOG_INFO("Connection closed by relay");
            } else if (errno != EINTR) {
                LOG_ERROR("Receive error: %s", strerror(errno));
            }
            client->connected = false;
            break;
        }

        client->bytes_received += bytes;

        if (bytes < (ssize_t)sizeof(message_header_t)) continue;

        message_t* msg = (message_t*)buffer;

        int validation = message_validate(msg);
        if (validation != 0) {
            LOG_WARN("Invalid message received (error: %d)", validation);
            continue;
        }

        client->messages_received++;
        LOG_DEBUG("Received %s from %s",
                  message_type_string(msg->header.type),
                  msg->header.sender_id);

        // ── PONG ──
        if (msg->header.type == MSG_PONG) {
            payload_ping_t* pong = (payload_ping_t*)msg->payload;
            client->rtt_ms = get_timestamp_ms() - pong->ping_time;
            LOG_DEBUG("PONG received (id: %u, RTT: %lu ms)",
                      pong->ping_id, client->rtt_ms);
        }

        // ── VOTE REQUEST ──
        if (msg->header.type == MSG_GROUP_VOTE_REQ) {
            payload_vote_request_t* vote_req = (payload_vote_request_t*)msg->payload;
            strncpy(client->pending_vote_request_id, vote_req->request_id, MAX_ID_LENGTH - 1);
            strncpy(client->pending_vote_requester, vote_req->requester_id, MAX_ID_LENGTH - 1);
            strncpy(client->pending_vote_group, vote_req->group_id, MAX_ID_LENGTH - 1);
            client->has_pending_vote = true;
            LOG_INFO("=== VOTE REQUEST ===");
            LOG_INFO("User '%s' wants to join your group.", vote_req->requester_id);
            LOG_INFO("Press 'y' to approve or 'n' to reject");
        }

        // ── GROUP APPROVED ──
        if (msg->header.type == MSG_GROUP_APPROVED) {
            payload_group_result_t* result = (payload_group_result_t*)msg->payload;
            strncpy(client->group_id, result->group_id, MAX_ID_LENGTH - 1);
            strncpy(client->group_name, result->group_name, MAX_GROUP_NAME - 1);
            client->in_group = true;
            LOG_INFO("=== JOINED GROUP ===");
            LOG_INFO("Group: %s (%s)", result->group_name, result->group_id);
            LOG_INFO("Members: %u", result->member_count);
        }

        // ── GROUP REJECTED ──
        if (msg->header.type == MSG_GROUP_REJECTED) {
            LOG_WARN("=== JOIN REJECTED ===");
            LOG_WARN("Your request to join the group was rejected.");
        }

        // ── GROUP INFO ──
        if (msg->header.type == MSG_GROUP_INFO) {
            payload_group_info_t* info = (payload_group_info_t*)msg->payload;
            LOG_INFO("=== GROUP PEERS ===");
            for (uint32_t i = 0; i < info->peer_count; i++) {
                LOG_INFO("  - %s (%s:%d)",
                         info->peers[i].id, info->peers[i].ip, info->peers[i].port);
            }
        }

        // ── FILE ANNOUNCE ──
        if (msg->header.type == MSG_FILE_ANNOUNCE) {
            payload_file_announce_t* announce = (payload_file_announce_t*)msg->payload;
            if (strcmp(msg->header.sender_id, client->id) != 0) {
                char hash_hex[65];
                hash_to_hex((const uint8_t*)announce->file_hash, hash_hex, sizeof(hash_hex));
                LOG_INFO("=== FILE ANNOUNCED ===");
                LOG_INFO("File: %s (hash: %.16s...)", announce->filename, hash_hex);
                LOG_INFO("From: %s", msg->header.sender_id);

                uint16_t owner_port = P2P_LISTEN_PORT_BASE;
                const char* pid_str = msg->header.sender_id + 5;
                if (pid_str) {
                    int pid = atoi(pid_str);
                    owner_port = P2P_LISTEN_PORT_BASE + (pid % 1000);
                }

                file_manager_register_file(&client->file_mgr, announce,
                                           "127.0.0.1", owner_port);
            }
        }

        // ── FILE LIST REQUEST ──
        if (msg->header.type == MSG_FILE_LIST) {
            LOG_INFO("Peer %s is requesting file list", msg->header.sender_id);
            for (int i = 0; i < client->file_mgr.file_count; i++) {
                shared_file_t* file = &client->file_mgr.files[i];
                if (file->metadata.is_complete &&
                    strcmp(file->owner_id, client->id) == 0) {
                    client_announce_file(client, file);
                }
            }
        }

        // ── NAT INFO ──
        if (msg->header.type == MSG_NAT_INFO) {
            payload_nat_info_t* nat_info = (payload_nat_info_t*)msg->payload;
            nat_set_info(&client->nat_mgr, nat_info);
            LOG_INFO("NAT: Public endpoint discovered: %s:%d (type: %s)",
                     nat_info->public_ip, nat_info->public_port,
                     nat_type_string((nat_type_t)nat_info->nat_type));
        }

        // ── NAT PUNCH INSTRUCTION ──
        if (msg->header.type == MSG_NAT_PUNCH_INSTR) {
            payload_punch_instruction_t* instr =
                (payload_punch_instruction_t*)msg->payload;
            LOG_INFO("NAT: Received punch instruction for peer %s", instr->peer_id);

            int fd = nat_handle_punch_instruction(&client->nat_mgr, instr);

            // Report result to relay
            message_t result_msg;
            memset(&result_msg, 0, sizeof(result_msg));
            message_header_init(&result_msg.header, MSG_NAT_PUNCH_RESULT);
            strncpy(result_msg.header.sender_id, client->id, MAX_ID_LENGTH - 1);

            payload_punch_result_t* result =
                (payload_punch_result_t*)result_msg.payload;
            strncpy(result->peer_id, instr->peer_id, sizeof(result->peer_id) - 1);
            result->success = (fd >= 0) ? 1 : 0;
            result_msg.header.payload_length = sizeof(payload_punch_result_t);

            client_send_message(client, &result_msg);
        }

        // ── USER CALLBACK ──
        if (client->on_message) {
            client->on_message(msg, client->callback_user_data);
        }
    }

    LOG_DEBUG("Receive thread exiting");
    return NULL;
}

/*  Function: client_ping_thread
    Description:
    Periodically sends PING messages to the relay to keep the connection alive.
*/
void* client_ping_thread(void* arg) {
    p2p_client_t* client = (p2p_client_t*)arg;

    LOG_DEBUG("Auto-ping thread started (interval: %d ms)", PING_INTERVAL_MS);

    while (client->ping_thread_running && client->connected) {
        usleep(PING_INTERVAL_MS * 1000);

        if (!client->connected || !client->ping_thread_running) break;

        if (client_send_ping(client) == 0) {
            LOG_TRACE("Auto-ping sent (id: %u)", client->ping_counter);
        }
    }

    LOG_DEBUG("Auto-ping thread exiting");
    return NULL;
}