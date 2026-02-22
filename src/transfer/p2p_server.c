#include "p2p_server.h"
#include "../common/logging.h"
#include "../common/protocol.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static file_manager_t* g_file_mgr = NULL;

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
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

static void* p2p_client_handler(void* arg) {
    int client_socket = *(int*)arg;
    free(arg);

    message_t msg;
    if (recv_msg(client_socket, &msg, TRANSFER_TIMEOUT_MS) != 0 ||
        msg.header.type != MSG_FILE_REQUEST) {
        close(client_socket);
        return NULL;
    }

    payload_file_request_t* req = (payload_file_request_t*)msg.payload;
    shared_file_t* file = file_manager_find_by_hash(g_file_mgr, (const uint8_t*)req->file_hash);
    if (!file || !file->metadata.is_complete) {
        message_t nack;
        memset(&nack, 0, sizeof(nack));
        message_header_init(&nack.header, MSG_NACK);
        send_msg(client_socket, &nack);
        close(client_socket);
        return NULL;
    }

    message_t meta_msg;
    memset(&meta_msg, 0, sizeof(meta_msg));
    message_header_init(&meta_msg.header, MSG_FILE_METADATA);
    payload_file_metadata_t* meta = (payload_file_metadata_t*)meta_msg.payload;
    memcpy(meta->file_hash, file->metadata.file_hash, FILE_HASH_SIZE);
    strncpy(meta->filename, file->metadata.filename, MAX_FILENAME - 1);
    meta->file_size = file->metadata.file_size;
    meta->chunk_count = file->metadata.chunk_count;
    meta_msg.header.payload_length = sizeof(payload_file_metadata_t);
    if (send_msg(client_socket, &meta_msg) != 0) { close(client_socket); return NULL; }

    uint32_t chunks_sent = 0;
    while (1) {
        if (recv_msg(client_socket, &msg, TRANSFER_TIMEOUT_MS) != 0) break;
        if (msg.header.type == MSG_TRANSFER_COMPLETE) break;
        if (msg.header.type != MSG_CHUNK_REQUEST) continue;

        payload_chunk_request_t* chunk_req = (payload_chunk_request_t*)msg.payload;
        chunk_t chunk;
        if (chunk_read(file->metadata.file_path, chunk_req->chunk_index, &chunk) != 0) continue;

        message_t chunk_msg;
        memset(&chunk_msg, 0, sizeof(chunk_msg));
        message_header_init(&chunk_msg.header, MSG_CHUNK_DATA);
        payload_chunk_data_t* cd = (payload_chunk_data_t*)chunk_msg.payload;
        memcpy(cd->file_hash, file->metadata.file_hash, FILE_HASH_SIZE);
        cd->chunk_index = chunk.index;
        cd->chunk_size = chunk.size;
        memcpy(cd->chunk_hash, chunk.hash, FILE_HASH_SIZE);
        memcpy(cd->data, chunk.data, chunk.size);
        chunk_msg.header.payload_length = sizeof(payload_chunk_data_t);
        if (send_msg(client_socket, &chunk_msg) != 0) break;
        chunks_sent++;
    }

    close(client_socket);
    return NULL;
}

static void* p2p_accept_thread(void* arg) {
    p2p_server_t* server = (p2p_server_t*)arg;
    while (server->running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(server->server_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) { usleep(10000); continue; }

        int* sock_arg = malloc(sizeof(int));
        *sock_arg = client_fd;
        pthread_t handler;
        pthread_create(&handler, NULL, p2p_client_handler, sock_arg);
        pthread_detach(handler);
    }
    return NULL;
}

int p2p_server_init(p2p_server_t* server, uint16_t port) {
    memset(server, 0, sizeof(p2p_server_t));
    server->port = port;
    pthread_mutex_init(&server->send_mutex, NULL);

    server->server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->server_fd < 0) return -1;

    int opt = 1;
    setsockopt(server->server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server->server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(server->server_fd);
        return -1;
    }
    if (listen(server->server_fd, 5) < 0) { close(server->server_fd); return -1; }
    set_nonblocking(server->server_fd);
    return 0;
}

int p2p_server_start(p2p_server_t* server, file_manager_t* file_mgr) {
    g_file_mgr = file_mgr;
    server->running = true;
    return pthread_create(&server->accept_thread, NULL, p2p_accept_thread, server);
}

void p2p_server_stop(p2p_server_t* server) {
    server->running = false;
    pthread_join(server->accept_thread, NULL);
}

void p2p_server_cleanup(p2p_server_t* server) {
    if (server->server_fd > 0) close(server->server_fd);
    pthread_mutex_destroy(&server->send_mutex);
}