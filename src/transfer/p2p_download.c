#include "p2p_download.h"
#include "chunking.h"
#include "../common/logging.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int send_msg(int sock, message_t* msg) {
    size_t total = message_total_size(msg);
    ssize_t sent = send(sock, msg, total, 0);
    return (sent == (ssize_t)total) ? 0 : -1;
}

static int recv_msg(int sock, message_t* msg, int timeout_ms) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
    if (select(sock + 1, &fds, NULL, NULL, &tv) <= 0) return -1;
    ssize_t received = recv(sock, msg, sizeof(message_t), 0);
    if (received < (ssize_t)sizeof(message_header_t)) return -1;
    return message_validate(msg);
}

int p2p_download_file(const char* peer_ip, uint16_t peer_port,
                      const uint8_t* file_hash, const char* save_path,
                      transfer_progress_cb progress_cb,
                      transfer_complete_cb complete_cb,
                      void* user_data) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(peer_port);
    inet_pton(AF_INET, peer_ip, &addr.sin_addr);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(sock); return -1; }

    message_t req_msg;
    memset(&req_msg, 0, sizeof(req_msg));
    message_header_init(&req_msg.header, MSG_FILE_REQUEST);
    payload_file_request_t* req = (payload_file_request_t*)req_msg.payload;
    memcpy(req->file_hash, file_hash, FILE_HASH_SIZE);
    req_msg.header.payload_length = sizeof(payload_file_request_t);
    if (send_msg(sock, &req_msg) != 0) { close(sock); return -1; }

    message_t meta_msg;
    if (recv_msg(sock, &meta_msg, TRANSFER_TIMEOUT_MS) != 0 ||
        meta_msg.header.type == MSG_NACK ||
        meta_msg.header.type != MSG_FILE_METADATA) { close(sock); return -1; }

    payload_file_metadata_t* meta = (payload_file_metadata_t*)meta_msg.payload;

    file_metadata_t file_meta = {0};
    memcpy(file_meta.file_hash, meta->file_hash, FILE_HASH_SIZE);
    strncpy(file_meta.filename, meta->filename, MAX_FILENAME - 1);
    file_meta.file_size = meta->file_size;
    file_meta.chunk_count = meta->chunk_count;

    transfer_context_t* ctx = transfer_context_create_recv(&file_meta, save_path);
    if (!ctx) { close(sock); return -1; }
    ctx->state = TRANSFER_IN_PROGRESS;
    ctx->started_at = get_timestamp_ms();
    ctx->peer_socket = sock;

    int fd = open(save_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) { ftruncate(fd, meta->file_size); close(fd); }

    for (uint32_t i = 0; i < meta->chunk_count; i++) {
        message_t chunk_req;
        memset(&chunk_req, 0, sizeof(chunk_req));
        message_header_init(&chunk_req.header, MSG_CHUNK_REQUEST);
        payload_chunk_request_t* cr = (payload_chunk_request_t*)chunk_req.payload;
        memcpy(cr->file_hash, file_hash, FILE_HASH_SIZE);
        cr->chunk_index = i;
        chunk_req.header.payload_length = sizeof(payload_chunk_request_t);
        if (send_msg(sock, &chunk_req) != 0) { ctx->state = TRANSFER_FAILED; break; }

        message_t chunk_msg;
        if (recv_msg(sock, &chunk_msg, TRANSFER_TIMEOUT_MS) != 0 ||
            chunk_msg.header.type != MSG_CHUNK_DATA) { ctx->state = TRANSFER_FAILED; break; }

        payload_chunk_data_t* cd = (payload_chunk_data_t*)chunk_msg.payload;
        uint8_t calc_hash[FILE_HASH_SIZE];
        sha256_hash(cd->data, cd->chunk_size, calc_hash);
        if (!hash_compare(calc_hash, (const uint8_t*)cd->chunk_hash)) {
            i--; ctx->retries++;
            if (ctx->retries > CHUNK_RETRY_COUNT * meta->chunk_count) { ctx->state = TRANSFER_FAILED; break; }
            continue;
        }

        chunk_t chunk = { .index = cd->chunk_index, .size = cd->chunk_size };
        memcpy(chunk.data, cd->data, chunk.size);
        if (chunk_write(save_path, i, &chunk) != 0) { ctx->state = TRANSFER_FAILED; break; }
        transfer_update_progress(ctx, i);
        if (progress_cb) progress_cb(ctx, user_data);
    }

    message_t complete_msg;
    memset(&complete_msg, 0, sizeof(complete_msg));
    message_header_init(&complete_msg.header, MSG_TRANSFER_COMPLETE);
    payload_transfer_complete_t* tc = (payload_transfer_complete_t*)complete_msg.payload;
    memcpy(tc->file_hash, file_hash, FILE_HASH_SIZE);
    tc->chunks_received = ctx->chunks_completed;
    tc->success = (ctx->state != TRANSFER_FAILED);
    complete_msg.header.payload_length = sizeof(payload_transfer_complete_t);
    send_msg(sock, &complete_msg);
    close(sock);

    bool success = (ctx->state != TRANSFER_FAILED) && transfer_verify_complete(ctx);
    if (complete_cb) complete_cb(ctx, success, user_data);
    transfer_context_free(ctx);
    return success ? 0 : -1;
}

int p2p_download_file_with_fd(int peer_fd, const uint8_t* file_hash,
                               const char* save_path,
                               void (*progress_cb)(uint32_t chunk, uint32_t total, void* data),
                               void (*complete_cb)(bool success, void* data),
                               void* user_data) {
    message_t req;
    memset(&req, 0, sizeof(req));
    message_header_init(&req.header, MSG_FILE_REQUEST);
    memcpy(req.payload, file_hash, FILE_HASH_SIZE);
    req.header.payload_length = FILE_HASH_SIZE;
    if (send(peer_fd, &req, message_total_size(&req), 0) <= 0) return -1;

    uint8_t buffer[READ_BUFFER_SIZE];
    ssize_t received = recv(peer_fd, buffer, sizeof(buffer), 0);
    if (received <= 0) return -1;
    message_t* meta_msg = (message_t*)buffer;
    if (meta_msg->header.type != MSG_FILE_METADATA) return -1;

    payload_file_metadata_t* meta = (payload_file_metadata_t*)meta_msg->payload;
    uint32_t chunk_count = meta->chunk_count;
    uint64_t file_size = meta->file_size;

    FILE* fp = fopen(save_path, "wb");
    if (!fp) return -1;
    if (fseek(fp, file_size - 1, SEEK_SET) == 0) { fputc(0, fp); fseek(fp, 0, SEEK_SET); }

    uint32_t chunks_received = 0;
    for (uint32_t i = 0; i < chunk_count; i++) {
        message_t chunk_req;
        memset(&chunk_req, 0, sizeof(chunk_req));
        message_header_init(&chunk_req.header, MSG_CHUNK_REQUEST);
        payload_chunk_request_t* cr = (payload_chunk_request_t*)chunk_req.payload;
        memcpy(cr->file_hash, file_hash, FILE_HASH_SIZE);
        cr->chunk_index = i;
        chunk_req.header.payload_length = sizeof(payload_chunk_request_t);
        if (send(peer_fd, &chunk_req, message_total_size(&chunk_req), 0) <= 0) { fclose(fp); return -1; }

        received = recv(peer_fd, buffer, sizeof(buffer), 0);
        if (received <= 0) { fclose(fp); return -1; }
        message_t* chunk_msg = (message_t*)buffer;
        if (chunk_msg->header.type != MSG_CHUNK_DATA) { fclose(fp); return -1; }

        payload_chunk_data_t* cd = (payload_chunk_data_t*)chunk_msg->payload;
        fseek(fp, (long)cd->chunk_index * CHUNK_SIZE, SEEK_SET);
        fwrite(cd->data, 1, cd->chunk_size, fp);
        chunks_received++;
        if (progress_cb) progress_cb(chunks_received, chunk_count, user_data);
    }

    fclose(fp);

    message_t complete;
    memset(&complete, 0, sizeof(complete));
    message_header_init(&complete.header, MSG_TRANSFER_COMPLETE);
    payload_transfer_complete_t* tc = (payload_transfer_complete_t*)complete.payload;
    memcpy(tc->file_hash, file_hash, FILE_HASH_SIZE);
    tc->success = 1;
    tc->chunks_received = chunks_received;
    complete.header.payload_length = sizeof(payload_transfer_complete_t);
    send(peer_fd, &complete, message_total_size(&complete), 0);

    bool success = (chunks_received == chunk_count);
    if (complete_cb) complete_cb(success, user_data);
    return success ? 0 : -1;
}

transfer_state_t p2p_get_transfer_state(transfer_context_t* ctx) {
    return ctx ? ctx->state : TRANSFER_IDLE;
}

void p2p_cancel_transfer(transfer_context_t* ctx) {
    if (!ctx) return;
    ctx->state = TRANSFER_FAILED;
    if (ctx->peer_socket > 0) { close(ctx->peer_socket); ctx->peer_socket = -1; }
}