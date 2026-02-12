#include "p2p_transfer.h"
#include "../common/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

// ============================================
// HELPER FUNCTIONS
// ============================================

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int send_message(int sock, message_t* msg) {
    size_t total = message_total_size(msg);
    ssize_t sent = send(sock, msg, total, 0);
    return (sent == (ssize_t)total) ? 0 : -1;
}

static int recv_message(int sock, message_t* msg, int timeout_ms) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    int ret = select(sock + 1, &fds, NULL, NULL, &tv);
    if (ret <= 0) return -1;
    
    ssize_t received = recv(sock, msg, sizeof(message_t), 0);
    if (received < (ssize_t)sizeof(message_header_t)) return -1;
    
    return message_validate(msg);
}

// ============================================
// FILE MANAGER IMPLEMENTATION
// ============================================

int file_manager_init(file_manager_t* mgr, const char* shared_dir, 
                      const char* download_dir) {
    memset(mgr, 0, sizeof(file_manager_t));
    pthread_mutex_init(&mgr->mutex, NULL);
    
    strncpy(mgr->shared_dir, shared_dir, sizeof(mgr->shared_dir) - 1);
    strncpy(mgr->download_dir, download_dir, sizeof(mgr->download_dir) - 1);
    
    // Create directories if they don't exist
    mkdir(shared_dir, 0755);
    mkdir(download_dir, 0755);
    
    LOG_INFO("File manager initialized");
    LOG_INFO("Shared dir: %s", shared_dir);
    LOG_INFO("Download dir: %s", download_dir);
    
    return 0;
}

void file_manager_cleanup(file_manager_t* mgr) {
    pthread_mutex_lock(&mgr->mutex);
    
    for (int i = 0; i < mgr->file_count; i++) {
        if (mgr->files[i].metadata.chunk_hashes) {
            free(mgr->files[i].metadata.chunk_hashes);
        }
    }
    mgr->file_count = 0;
    
    pthread_mutex_unlock(&mgr->mutex);
    pthread_mutex_destroy(&mgr->mutex);
    
    LOG_INFO("File manager cleanup complete");
}

int file_manager_share_file(file_manager_t* mgr, const char* filepath,
                            const char* owner_id) {
    pthread_mutex_lock(&mgr->mutex);
    
    if (mgr->file_count >= MAX_SHARED_FILES) {
        LOG_WARN("Cannot share file: max files reached");
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    // Create metadata
    file_metadata_t* meta = file_metadata_create(filepath);
    if (!meta) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    // Check if already shared
    for (int i = 0; i < mgr->file_count; i++) {
        if (hash_compare(mgr->files[i].metadata.file_hash, meta->file_hash)) {
            LOG_WARN("File already shared: %s", filepath);
            file_metadata_free(meta);
            pthread_mutex_unlock(&mgr->mutex);
            return -2;
        }
    }
    
    // Add to list
    shared_file_t* entry = &mgr->files[mgr->file_count];
    memcpy(&entry->metadata, meta, sizeof(file_metadata_t));
    entry->metadata.chunk_hashes = meta->chunk_hashes;
    meta->chunk_hashes = NULL;
    
    strncpy(entry->owner_id, owner_id, MAX_ID_LENGTH - 1);
    entry->announced_at = get_timestamp_ms();
    entry->available = true;
    
    mgr->file_count++;
    
    char hex[65];
    hash_to_hex(entry->metadata.file_hash, hex, sizeof(hex));
    LOG_INFO("File shared: %s (hash: %s)", entry->metadata.filename, hex);
    
    free(meta);
    pthread_mutex_unlock(&mgr->mutex);
    return 0;
}

int file_manager_register_file(file_manager_t* mgr,
                               const payload_file_announce_t* announce,
                               const char* owner_ip, uint16_t owner_port) {
    pthread_mutex_lock(&mgr->mutex);
    
    // Check if already known
    for (int i = 0; i < mgr->file_count; i++) {
        if (memcmp(mgr->files[i].metadata.file_hash, announce->file_hash, FILE_HASH_SIZE) == 0) {
            // Update availability and connection info
            mgr->files[i].available = true;
            strncpy(mgr->files[i].owner_ip, owner_ip, sizeof(mgr->files[i].owner_ip) - 1);
            mgr->files[i].owner_port = owner_port;
            pthread_mutex_unlock(&mgr->mutex);
            LOG_DEBUG("Updated existing file entry: %s", announce->filename);
            return 0;
        }
    }
    
    if (mgr->file_count >= MAX_SHARED_FILES) {
        pthread_mutex_unlock(&mgr->mutex);
        LOG_WARN("File manager full, cannot register file");
        return -1;
    }
    
    // Add new entry
    shared_file_t* entry = &mgr->files[mgr->file_count];
    memset(entry, 0, sizeof(shared_file_t));
    
    memcpy(entry->metadata.file_hash, announce->file_hash, FILE_HASH_SIZE);
    strncpy(entry->metadata.filename, announce->filename, MAX_FILENAME - 1);
    entry->metadata.file_size = announce->file_size;
    entry->metadata.chunk_count = announce->chunk_count;
    entry->metadata.is_complete = false;  // We don't have it yet
    
    strncpy(entry->owner_ip, owner_ip, sizeof(entry->owner_ip) - 1);
    entry->owner_port = owner_port;
    entry->available = true;
    
    mgr->file_count++;
    
    LOG_INFO("Registered remote file: %s (%lu bytes) from %s:%d",
             entry->metadata.filename, entry->metadata.file_size,
             owner_ip, owner_port);
    
    pthread_mutex_unlock(&mgr->mutex);
    return 0;
}

shared_file_t* file_manager_find_by_hash(file_manager_t* mgr,
                                          const uint8_t* file_hash) {
    for (int i = 0; i < mgr->file_count; i++) {
        if (hash_compare(mgr->files[i].metadata.file_hash, file_hash)) {
            return &mgr->files[i];
        }
    }
    return NULL;
}

int file_manager_get_file_list(file_manager_t* mgr,
                               payload_file_list_response_t* response) {
    pthread_mutex_lock(&mgr->mutex);
    
    response->file_count = 0;
    
    for (int i = 0; i < mgr->file_count && response->file_count < 32; i++) {
        if (mgr->files[i].available) {
            memcpy(response->files[response->file_count].file_hash,
                   mgr->files[i].metadata.file_hash, FILE_HASH_SIZE);
            strncpy(response->files[response->file_count].filename,
                   mgr->files[i].metadata.filename, MAX_FILENAME - 1);
            response->files[response->file_count].file_size = 
                mgr->files[i].metadata.file_size;
            strncpy(response->files[response->file_count].owner_id,
                   mgr->files[i].owner_id, MAX_ID_LENGTH - 1);
            response->file_count++;
        }
    }
    
    pthread_mutex_unlock(&mgr->mutex);
    return response->file_count;
}

int file_manager_remove_file(file_manager_t* mgr, const uint8_t* file_hash) {
    pthread_mutex_lock(&mgr->mutex);
    
    for (int i = 0; i < mgr->file_count; i++) {
        if (hash_compare(mgr->files[i].metadata.file_hash, file_hash)) {
            if (mgr->files[i].metadata.chunk_hashes) {
                free(mgr->files[i].metadata.chunk_hashes);
            }
            
            // Shift remaining
            for (int j = i; j < mgr->file_count - 1; j++) {
                mgr->files[j] = mgr->files[j + 1];
            }
            mgr->file_count--;
            
            pthread_mutex_unlock(&mgr->mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&mgr->mutex);
    return -1;
}

// ============================================
// P2P SERVER IMPLEMENTATION
// ============================================

static file_manager_t* g_file_mgr = NULL;

static void* p2p_client_handler(void* arg) {
    int client_socket = *(int*)arg;
    free(arg);
    
    LOG_INFO("P2P client handler started (socket: %d)", client_socket);
    
    // Receive file request
    message_t msg;
    if (recv_message(client_socket, &msg, TRANSFER_TIMEOUT_MS) != 0) {
        LOG_WARN("Failed to receive request");
        close(client_socket);
        return NULL;
    }
    
    if (msg.header.type != MSG_FILE_REQUEST) {
        LOG_WARN("Unexpected message type: %d", msg.header.type);
        close(client_socket);
        return NULL;
    }
    
    payload_file_request_t* req = (payload_file_request_t*)msg.payload;
    
    char hex[65];
    hash_to_hex((const uint8_t*)req->file_hash, hex, sizeof(hex));
    LOG_INFO("File request received: %s", hex);
    
    // Find file
    shared_file_t* file = file_manager_find_by_hash(g_file_mgr,
                                                     (const uint8_t*)req->file_hash);
    if (!file || !file->metadata.is_complete) {
        LOG_WARN("File not found or incomplete");
        
        message_t nack;
        memset(&nack, 0, sizeof(nack));
        message_header_init(&nack.header, MSG_NACK);
        send_message(client_socket, &nack);
        close(client_socket);
        return NULL;
    }
    
    // Send metadata
    message_t meta_msg;
    memset(&meta_msg, 0, sizeof(meta_msg));
    message_header_init(&meta_msg.header, MSG_FILE_METADATA);
    
    payload_file_metadata_t* meta = (payload_file_metadata_t*)meta_msg.payload;
    memcpy(meta->file_hash, file->metadata.file_hash, FILE_HASH_SIZE);
    strncpy(meta->filename, file->metadata.filename, MAX_FILENAME - 1);
    meta->file_size = file->metadata.file_size;
    meta->chunk_count = file->metadata.chunk_count;
    meta_msg.header.payload_length = sizeof(payload_file_metadata_t);
    
    if (send_message(client_socket, &meta_msg) != 0) {
        close(client_socket);
        return NULL;
    }
    
    LOG_INFO("Metadata sent, starting transfer of %u chunks", meta->chunk_count);
    
    // Serve chunk requests
    uint32_t chunks_sent = 0;
    while (1) {
        if (recv_message(client_socket, &msg, TRANSFER_TIMEOUT_MS) != 0) {
            LOG_WARN("Timeout waiting for chunk request");
            break;
        }
        
        if (msg.header.type == MSG_TRANSFER_COMPLETE) {
            LOG_INFO("Transfer complete acknowledged");
            break;
        }
        
        if (msg.header.type != MSG_CHUNK_REQUEST) {
            LOG_WARN("Unexpected message: %d", msg.header.type);
            continue;
        }
        
        payload_chunk_request_t* chunk_req = (payload_chunk_request_t*)msg.payload;
        
        // Read and send chunk
        chunk_t chunk;
        if (chunk_read(file->metadata.file_path, chunk_req->chunk_index, &chunk) != 0) {
            LOG_ERROR("Failed to read chunk %u", chunk_req->chunk_index);
            continue;
        }
        
        message_t chunk_msg;
        memset(&chunk_msg, 0, sizeof(chunk_msg));
        message_header_init(&chunk_msg.header, MSG_CHUNK_DATA);
        
        payload_chunk_data_t* chunk_data = (payload_chunk_data_t*)chunk_msg.payload;
        memcpy(chunk_data->file_hash, file->metadata.file_hash, FILE_HASH_SIZE);
        chunk_data->chunk_index = chunk.index;
        chunk_data->chunk_size = chunk.size;
        memcpy(chunk_data->chunk_hash, chunk.hash, FILE_HASH_SIZE);
        memcpy(chunk_data->data, chunk.data, chunk.size);
        chunk_msg.header.payload_length = sizeof(payload_chunk_data_t);
        
        if (send_message(client_socket, &chunk_msg) != 0) {
            LOG_ERROR("Failed to send chunk %u", chunk.index);
            break;
        }
        
        chunks_sent++;
        
        if (chunks_sent % 100 == 0) {
            LOG_DEBUG("Sent %u chunks", chunks_sent);
        }
    }
    
    LOG_INFO("P2P session complete: sent %u chunks", chunks_sent);
    close(client_socket);
    return NULL;
}

static void* p2p_accept_thread(void* arg) {
    p2p_server_t* server = (p2p_server_t*)arg;
    
    LOG_INFO("P2P accept thread started on port %d", server->port);
    
    while (server->running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        int client_fd = accept(server->server_fd,
                               (struct sockaddr*)&client_addr, &addr_len);
        
        if (client_fd < 0) {
            if (errno != EWOULDBLOCK && errno != EAGAIN) {
                LOG_ERROR("Accept error: %s", strerror(errno));
            }
            usleep(10000);
            continue;
        }
        
        char client_ip[46];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        LOG_INFO("P2P connection from %s:%d", client_ip, ntohs(client_addr.sin_port));
        
        // Spawn handler thread
        int* sock_arg = malloc(sizeof(int));
        *sock_arg = client_fd;
        
        pthread_t handler_thread;
        pthread_create(&handler_thread, NULL, p2p_client_handler, sock_arg);
        pthread_detach(handler_thread);
    }
    
    return NULL;
}

int p2p_server_init(p2p_server_t* server, uint16_t port) {
    memset(server, 0, sizeof(p2p_server_t));
    server->port = port;
    pthread_mutex_init(&server->send_mutex, NULL);
    
    server->server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->server_fd < 0) {
        LOG_ERROR("Failed to create P2P socket: %s", strerror(errno));
        return -1;
    }
    
    int opt = 1;
    setsockopt(server->server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(server->server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("Failed to bind P2P port %d: %s", port, strerror(errno));
        close(server->server_fd);
        return -1;
    }
    
    if (listen(server->server_fd, 5) < 0) {
        LOG_ERROR("Failed to listen: %s", strerror(errno));
        close(server->server_fd);
        return -1;
    }
    
    set_nonblocking(server->server_fd);
    
    LOG_INFO("P2P server initialized on port %d", port);
    return 0;
}

int p2p_server_start(p2p_server_t* server, file_manager_t* file_mgr) {
    g_file_mgr = file_mgr;
    server->running = true;
    
    if (pthread_create(&server->accept_thread, NULL, p2p_accept_thread, server) != 0) {
        LOG_ERROR("Failed to create accept thread");
        return -1;
    }
    
    LOG_INFO("P2P server started");
    return 0;
}

void p2p_server_stop(p2p_server_t* server) {
    server->running = false;
    pthread_join(server->accept_thread, NULL);
    LOG_INFO("P2P server stopped");
}

void p2p_server_cleanup(p2p_server_t* server) {
    if (server->server_fd > 0) {
        close(server->server_fd);
    }
    pthread_mutex_destroy(&server->send_mutex);
    LOG_INFO("P2P server cleanup complete");
}

// ============================================
// P2P DOWNLOAD IMPLEMENTATION
// ============================================

int p2p_download_file(const char* peer_ip, uint16_t peer_port,
                      const uint8_t* file_hash, const char* save_path,
                      transfer_progress_cb progress_cb,
                      transfer_complete_cb complete_cb,
                      void* user_data) {
    LOG_INFO("Starting download from %s:%d", peer_ip, peer_port);
    
    // Connect to peer
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        LOG_ERROR("Socket creation failed");
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(peer_port);
    inet_pton(AF_INET, peer_ip, &addr.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("Connect failed: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    LOG_INFO("Connected to peer");
    
    // Send file request
    message_t req_msg;
    memset(&req_msg, 0, sizeof(req_msg));
    message_header_init(&req_msg.header, MSG_FILE_REQUEST);
    
    payload_file_request_t* req = (payload_file_request_t*)req_msg.payload;
    memcpy(req->file_hash, file_hash, FILE_HASH_SIZE);
    req_msg.header.payload_length = sizeof(payload_file_request_t);
    
    if (send_message(sock, &req_msg) != 0) {
        LOG_ERROR("Failed to send request");
        close(sock);
        return -1;
    }
    
    // Receive metadata
    message_t meta_msg;
    if (recv_message(sock, &meta_msg, TRANSFER_TIMEOUT_MS) != 0) {
        LOG_ERROR("Failed to receive metadata");
        close(sock);
        return -1;
    }
    
    if (meta_msg.header.type == MSG_NACK) {
        LOG_ERROR("File not available");
        close(sock);
        return -1;
    }
    
    if (meta_msg.header.type != MSG_FILE_METADATA) {
        LOG_ERROR("Unexpected response: %d", meta_msg.header.type);
        close(sock);
        return -1;
    }
    
    payload_file_metadata_t* meta = (payload_file_metadata_t*)meta_msg.payload;
    
    LOG_INFO("Downloading: %s (%lu bytes, %u chunks)",
             meta->filename, meta->file_size, meta->chunk_count);
    
    // Create transfer context
    file_metadata_t file_meta = {0};
    memcpy(file_meta.file_hash, meta->file_hash, FILE_HASH_SIZE);
    strncpy(file_meta.filename, meta->filename, MAX_FILENAME - 1);
    file_meta.file_size = meta->file_size;
    file_meta.chunk_count = meta->chunk_count;
    
    transfer_context_t* ctx = transfer_context_create_recv(&file_meta, save_path);
    if (!ctx) {
        close(sock);
        return -1;
    }
    
    ctx->state = TRANSFER_IN_PROGRESS;
    ctx->started_at = get_timestamp_ms();
    ctx->peer_socket = sock;
    
    // Pre-allocate file
    int fd = open(save_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        if (ftruncate(fd, meta->file_size) != 0) {
            LOG_WARN("Failed to pre-allocate file");
        }
        close(fd);
    }
    
    // Download chunks sequentially
    for (uint32_t i = 0; i < meta->chunk_count; i++) {
        // Request chunk
        message_t chunk_req;
        memset(&chunk_req, 0, sizeof(chunk_req));
        message_header_init(&chunk_req.header, MSG_CHUNK_REQUEST);
        
        payload_chunk_request_t* req_payload = (payload_chunk_request_t*)chunk_req.payload;
        memcpy(req_payload->file_hash, file_hash, FILE_HASH_SIZE);
        req_payload->chunk_index = i;
        chunk_req.header.payload_length = sizeof(payload_chunk_request_t);
        
        if (send_message(sock, &chunk_req) != 0) {
            LOG_ERROR("Failed to request chunk %u", i);
            ctx->state = TRANSFER_FAILED;
            break;
        }
        
        // Receive chunk
        message_t chunk_msg;
        if (recv_message(sock, &chunk_msg, TRANSFER_TIMEOUT_MS) != 0) {
            LOG_ERROR("Timeout receiving chunk %u", i);
            ctx->state = TRANSFER_FAILED;
            break;
        }
        
        if (chunk_msg.header.type != MSG_CHUNK_DATA) {
            LOG_ERROR("Unexpected response for chunk %u", i);
            ctx->state = TRANSFER_FAILED;
            break;
        }
        
        payload_chunk_data_t* chunk_data = (payload_chunk_data_t*)chunk_msg.payload;
        
        // Verify chunk hash
        uint8_t calc_hash[FILE_HASH_SIZE];
        sha256_hash(chunk_data->data, chunk_data->chunk_size, calc_hash);
        
        if (!hash_compare(calc_hash, (const uint8_t*)chunk_data->chunk_hash)) {
            LOG_WARN("Chunk %u hash mismatch, retrying", i);
            i--;  // Retry
            ctx->retries++;
            if (ctx->retries > CHUNK_RETRY_COUNT * meta->chunk_count) {
                ctx->state = TRANSFER_FAILED;
                break;
            }
            continue;
        }
        
        // Write chunk
        chunk_t chunk = {
            .index = chunk_data->chunk_index,
            .size = chunk_data->chunk_size
        };
        memcpy(chunk.data, chunk_data->data, chunk.size);
        
        if (chunk_write(save_path, i, &chunk) != 0) {
            LOG_ERROR("Failed to write chunk %u", i);
            ctx->state = TRANSFER_FAILED;
            break;
        }
        
        transfer_update_progress(ctx, i);
        
        if (progress_cb) {
            progress_cb(ctx, user_data);
        }
        
        // Progress logging
        if ((i + 1) % 100 == 0 || i == meta->chunk_count - 1) {
            double percent = (double)(i + 1) / meta->chunk_count * 100.0;
            LOG_INFO("Progress: %.1f%% (%u/%u chunks, %.2f KB/s)",
                     percent, i + 1, meta->chunk_count,
                     ctx->transfer_rate / 1024.0);
        }
    }
    
    // Send completion
    message_t complete_msg;
    memset(&complete_msg, 0, sizeof(complete_msg));
    message_header_init(&complete_msg.header, MSG_TRANSFER_COMPLETE);
    
    payload_transfer_complete_t* complete = (payload_transfer_complete_t*)complete_msg.payload;
    memcpy(complete->file_hash, file_hash, FILE_HASH_SIZE);
    complete->chunks_received = ctx->chunks_completed;
    complete->success = (ctx->state != TRANSFER_FAILED);
    complete_msg.header.payload_length = sizeof(payload_transfer_complete_t);
    
    send_message(sock, &complete_msg);
    close(sock);
    
    // Verify final file
    bool success = false;
    if (ctx->state != TRANSFER_FAILED) {
        success = transfer_verify_complete(ctx);
    }
    
    if (complete_cb) {
        complete_cb(ctx, success, user_data);
    }
    
    transfer_context_free(ctx);
    
    return success ? 0 : -1;
}

transfer_state_t p2p_get_transfer_state(transfer_context_t* ctx) {
    return ctx ? ctx->state : TRANSFER_IDLE;
}

void p2p_cancel_transfer(transfer_context_t* ctx) {
    if (ctx) {
        ctx->state = TRANSFER_FAILED;
        if (ctx->peer_socket > 0) {
            close(ctx->peer_socket);
            ctx->peer_socket = -1;
        }
    }
}

int p2p_download_file_with_fd(int peer_fd, const uint8_t* file_hash,
                               const char* save_path,
                               void (*progress_cb)(uint32_t chunk, uint32_t total, void* data),
                               void (*complete_cb)(bool success, void* data),
                               void* user_data) {
    // Send file request
    message_t req;
    memset(&req, 0, sizeof(req));
    message_header_init(&req.header, MSG_FILE_REQUEST);
    memcpy(req.payload, file_hash, FILE_HASH_SIZE);
    req.header.payload_length = FILE_HASH_SIZE;
    
    ssize_t sent = send(peer_fd, &req, message_total_size(&req), 0);
    if (sent <= 0) {
        LOG_ERROR("P2P: Failed to send file request");
        return -1;
    }
    
    // Receive metadata
    uint8_t buffer[READ_BUFFER_SIZE];
    ssize_t received = recv(peer_fd, buffer, sizeof(buffer), 0);
    if (received <= 0) {
        LOG_ERROR("P2P: Failed to receive metadata");
        return -1;
    }
    
    message_t* meta_msg = (message_t*)buffer;
    if (meta_msg->header.type != MSG_FILE_METADATA) {
        LOG_ERROR("P2P: Expected FILE_METADATA, got %s", 
                  message_type_string(meta_msg->header.type));
        return -1;
    }
    
    payload_file_metadata_t* meta = (payload_file_metadata_t*)meta_msg->payload;
    uint32_t chunk_count = meta->chunk_count;
    uint64_t file_size = meta->file_size;
    
    LOG_INFO("P2P: Downloading %s (%lu bytes, %u chunks)", 
             meta->filename, file_size, chunk_count);
    
    // Create/open output file
    FILE* fp = fopen(save_path, "wb");
    if (!fp) {
        LOG_ERROR("P2P: Cannot create file %s: %s", save_path, strerror(errno));
        return -1;
    }
    
    // Pre-allocate file
    if (fseek(fp, file_size - 1, SEEK_SET) == 0) {
        fputc(0, fp);
        fseek(fp, 0, SEEK_SET);
    }
    
    // Download chunks
    uint32_t chunks_received = 0;
    
    for (uint32_t i = 0; i < chunk_count; i++) {
        // Request chunk
        message_t chunk_req;
        memset(&chunk_req, 0, sizeof(chunk_req));
        message_header_init(&chunk_req.header, MSG_CHUNK_REQUEST);
        
        payload_chunk_request_t* cr = (payload_chunk_request_t*)chunk_req.payload;
        memcpy(cr->file_hash, file_hash, FILE_HASH_SIZE);
        cr->chunk_index = i;
        chunk_req.header.payload_length = sizeof(payload_chunk_request_t);
        
        sent = send(peer_fd, &chunk_req, message_total_size(&chunk_req), 0);
        if (sent <= 0) {
            LOG_ERROR("P2P: Failed to send chunk request %u", i);
            fclose(fp);
            return -1;
        }
        
        // Receive chunk data
        received = recv(peer_fd, buffer, sizeof(buffer), 0);
        if (received <= 0) {
            LOG_ERROR("P2P: Failed to receive chunk %u", i);
            fclose(fp);
            return -1;
        }
        
        message_t* chunk_msg = (message_t*)buffer;
        if (chunk_msg->header.type != MSG_CHUNK_DATA) {
            LOG_ERROR("P2P: Expected CHUNK_DATA, got %s", 
                      message_type_string(chunk_msg->header.type));
            fclose(fp);
            return -1;
        }
        
        payload_chunk_data_t* cd = (payload_chunk_data_t*)chunk_msg->payload;
        
        // Write chunk to file
        fseek(fp, (long)cd->chunk_index * CHUNK_SIZE, SEEK_SET);
        fwrite(cd->data, 1, cd->chunk_size, fp);
        
        chunks_received++;
        
        if (progress_cb) {
            progress_cb(chunks_received, chunk_count, user_data);
        }
        
        if (chunks_received % 100 == 0 || chunks_received == chunk_count) {
            LOG_DEBUG("P2P: Progress %u/%u chunks (%.1f%%)", 
                     chunks_received, chunk_count,
                     (float)chunks_received / chunk_count * 100.0f);
        }
    }
    
    fclose(fp);
    
    // Send transfer complete
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
    
    if (complete_cb) {
        complete_cb(success, user_data);
    }
    
    LOG_INFO("P2P: Transfer %s (%u/%u chunks)", 
             success ? "COMPLETE" : "INCOMPLETE", chunks_received, chunk_count);
    
    return success ? 0 : -1;
}