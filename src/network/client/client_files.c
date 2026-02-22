#include "client_files.h"
#include "client_messaging.h"
#include "../../common/logging.h"

#include <string.h>

int client_announce_file(p2p_client_t* client, shared_file_t* file) {
    if (!client || !client->connected || !client->in_group) {
        LOG_WARN("Cannot announce file: not connected or not in group");
        return -1;
    }

    message_t msg;
    memset(&msg, 0, sizeof(msg));
    message_header_init(&msg.header, MSG_FILE_ANNOUNCE);
    strncpy(msg.header.sender_id, client->id, MAX_ID_LENGTH - 1);

    payload_file_announce_t* payload = (payload_file_announce_t*)msg.payload;
    memcpy(payload->file_hash, file->metadata.file_hash, FILE_HASH_SIZE);
    strncpy(payload->filename, file->metadata.filename, MAX_FILENAME - 1);
    payload->file_size = file->metadata.file_size;
    payload->chunk_count = file->metadata.chunk_count;
    strncpy(payload->group_id, client->group_id, MAX_ID_LENGTH - 1);

    msg.header.payload_length = sizeof(payload_file_announce_t);

    char hash_hex[65];
    hash_to_hex(file->metadata.file_hash, hash_hex, sizeof(hash_hex));
    LOG_INFO("Announcing file to group: %s (hash: %.16s...)",
             file->metadata.filename, hash_hex);

    return client_send_message(client, &msg);
}

int client_request_file_list(p2p_client_t* client) {
    if (!client || !client->connected || !client->in_group) {
        LOG_WARN("Cannot request file list: not connected or not in group");
        return -1;
    }

    message_t msg;
    memset(&msg, 0, sizeof(msg));
    message_header_init(&msg.header, MSG_FILE_LIST);
    strncpy(msg.header.sender_id, client->id, MAX_ID_LENGTH - 1);

    payload_file_list_request_t* payload = (payload_file_list_request_t*)msg.payload;
    strncpy(payload->group_id, client->group_id, MAX_ID_LENGTH - 1);

    msg.header.payload_length = sizeof(payload_file_list_request_t);

    LOG_INFO("Requesting file list for group: %s", client->group_id);

    return client_send_message(client, &msg);
}