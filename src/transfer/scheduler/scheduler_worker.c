#include "scheduler_worker.h"
#include "priority_queue.h"
#include "bandwidth.h"
#include "scheduler_peers.h"
#include "../../common/logging.h"
#include "../../common/protocol.h"
#include "../chunking.h"

#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <time.h>

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int worker_download_chunk(download_worker_t* worker, download_task_t* task) {
    scheduler_t* sched = (scheduler_t*)worker->scheduler;
    int fd = task->peer_fd;
    if (fd < 0) return -1;

    task->request_sent_at = get_timestamp_ms();

    message_t req;
    memset(&req, 0, sizeof(req));
    message_header_init(&req.header, MSG_CHUNK_REQUEST);
    payload_chunk_request_t* cr = (payload_chunk_request_t*)req.payload;
    memcpy(cr->file_hash, sched->file_hash, FILE_HASH_SIZE);
    cr->chunk_index = task->chunk_index;
    req.header.payload_length = sizeof(payload_chunk_request_t);

    ssize_t sent = send(fd, &req, message_total_size(&req), 0);
    if (sent <= 0) return -1;

    uint8_t buffer[READ_BUFFER_SIZE];
    ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
    if (received <= 0) return -1;
    task->response_received_at = get_timestamp_ms();

    message_t* resp = (message_t*)buffer;
    if (resp->header.type != MSG_CHUNK_DATA) return -1;

    payload_chunk_data_t* cd = (payload_chunk_data_t*)resp->payload;
    uint8_t computed_hash[FILE_HASH_SIZE];
    sha256_hash(cd->data, cd->chunk_size, computed_hash);
    if (memcmp(computed_hash, cd->chunk_hash, FILE_HASH_SIZE) != 0) return -1;

    chunk_t chunk;
    memset(&chunk, 0, sizeof(chunk));
    chunk.index = cd->chunk_index;
    chunk.size = cd->chunk_size;
    memcpy(chunk.data, cd->data, cd->chunk_size);
    memcpy(chunk.hash, cd->chunk_hash, FILE_HASH_SIZE);
    if (chunk_write(sched->save_path, task->chunk_index, &chunk) != 0) return -1;

    task->bytes_received = cd->chunk_size;
    return 0;
}

void* worker_thread(void* arg) {
    download_worker_t* worker = (download_worker_t*)arg;
    scheduler_t* sched = (scheduler_t*)worker->scheduler;

    while (worker->running) {
        if (sched->paused) { usleep(100 * 1000); continue; }
        worker->idle = true;

        download_task_t task;
        if (pq_pop(&sched->queue, &task) != 0) {
            if (!worker->running || sched->complete) break;
            continue;
        }

        worker->idle = false;
        worker->has_task = true;
        worker->current_task = task;

        int result = worker_download_chunk(worker, &task);

        if (result == 0) {
            strategy_mark_downloaded(&sched->strategy, task.chunk_index);
            uint64_t elapsed = task.response_received_at - task.request_sent_at;
            bandwidth_record(&sched->global_bandwidth, task.bytes_received, elapsed);
            strategy_update_peer_metrics(&sched->strategy, task.peer_id,
                (double)task.bytes_received / ((double)elapsed / 1000.0), (double)elapsed);

            pthread_mutex_lock(&sched->mutex);
            sched->completed_chunks++;
            if (sched->on_progress)
                sched->on_progress(sched->completed_chunks, sched->total_chunks,
                                    bandwidth_get_rate(&sched->global_bandwidth),
                                    sched->callback_data);
            if (sched->completed_chunks >= sched->total_chunks) {
                sched->complete = true;
                pthread_cond_broadcast(&sched->complete_cond);
            }
            pthread_mutex_unlock(&sched->mutex);
        } else {
            strategy_mark_failed(&sched->strategy, task.chunk_index);
            strategy_record_peer_failure(&sched->strategy, task.peer_id);
            sched->total_retries++;
            if (task.retry_count < CHUNK_RETRY_COUNT) {
                const char* new_peer = select_best_peer(sched, task.chunk_index);
                if (new_peer) { sched->peer_switches++; schedule_chunk(sched, task.chunk_index, new_peer); }
                else { task.retry_count++; task.priority = TASK_PRIORITY_CRITICAL;
                       task.created_at = get_timestamp_ms(); pq_push(&sched->queue, &task); }
            }
        }
        worker->has_task = false;
    }
    return NULL;
}