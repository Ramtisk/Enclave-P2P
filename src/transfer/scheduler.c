#include "scheduler.h"
#include "../common/logging.h"
#include "../common/protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>

// ============================================
// HELPERS
// ============================================

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// ============================================
// PRIORITY QUEUE (min-heap: lower priority value = higher priority)
// ============================================

static void pq_init(priority_queue_t* pq) {
    memset(pq, 0, sizeof(priority_queue_t));
    pthread_mutex_init(&pq->mutex, NULL);
    pthread_cond_init(&pq->not_empty, NULL);
}

static void pq_destroy(priority_queue_t* pq) {
    pthread_mutex_destroy(&pq->mutex);
    pthread_cond_destroy(&pq->not_empty);
}

// Compare tasks: lower priority value wins, then earlier creation time
static bool task_less_than(const download_task_t* a, const download_task_t* b) {
    if (a->priority != b->priority) {
        return a->priority < b->priority;
    }
    return a->created_at < b->created_at;
}

static void pq_swap(priority_queue_t* pq, int i, int j) {
    download_task_t tmp = pq->tasks[i];
    pq->tasks[i] = pq->tasks[j];
    pq->tasks[j] = tmp;
}

static void pq_sift_up(priority_queue_t* pq, int index) {
    while (index > 0) {
        int parent = (index - 1) / 2;
        if (task_less_than(&pq->tasks[index], &pq->tasks[parent])) {
            pq_swap(pq, index, parent);
            index = parent;
        } else {
            break;
        }
    }
}

static void pq_sift_down(priority_queue_t* pq, int index) {
    int size = pq->count;
    while (1) {
        int smallest = index;
        int left = 2 * index + 1;
        int right = 2 * index + 2;

        if (left < size && task_less_than(&pq->tasks[left], &pq->tasks[smallest])) {
            smallest = left;
        }
        if (right < size && task_less_than(&pq->tasks[right], &pq->tasks[smallest])) {
            smallest = right;
        }

        if (smallest != index) {
            pq_swap(pq, index, smallest);
            index = smallest;
        } else {
            break;
        }
    }
}

int pq_push(priority_queue_t* pq, const download_task_t* task) {
    pthread_mutex_lock(&pq->mutex);

    if (pq->count >= SCHEDULER_MAX_QUEUE) {
        LOG_WARN("Scheduler: Priority queue full (%d)", SCHEDULER_MAX_QUEUE);
        pthread_mutex_unlock(&pq->mutex);
        return -1;
    }

    pq->tasks[pq->count] = *task;
    pq_sift_up(pq, pq->count);
    pq->count++;

    pthread_cond_signal(&pq->not_empty);
    pthread_mutex_unlock(&pq->mutex);
    return 0;
}

int pq_pop(priority_queue_t* pq, download_task_t* task_out) {
    pthread_mutex_lock(&pq->mutex);

    // Wait for a task with 1-second timeout (allows checking for shutdown)
    while (pq->count == 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;

        int ret = pthread_cond_timedwait(&pq->not_empty, &pq->mutex, &ts);
        if (ret != 0) {
            // Timeout or error
            pthread_mutex_unlock(&pq->mutex);
            return -1;
        }
    }

    *task_out = pq->tasks[0];
    pq->count--;

    if (pq->count > 0) {
        pq->tasks[0] = pq->tasks[pq->count];
        pq_sift_down(pq, 0);
    }

    pthread_mutex_unlock(&pq->mutex);
    return 0;
}

int pq_peek(const priority_queue_t* pq, download_task_t* task_out) {
    // Note: not thread-safe, caller must hold lock if needed
    if (pq->count == 0) return -1;
    *task_out = pq->tasks[0];
    return 0;
}

bool pq_is_empty(const priority_queue_t* pq) {
    return pq->count == 0;
}

// ============================================
// BANDWIDTH TRACKING
// ============================================

void bandwidth_init(bandwidth_tracker_t* bw) {
    memset(bw, 0, sizeof(bandwidth_tracker_t));
    bw->started_at = get_timestamp_ms();
}

void bandwidth_record(bandwidth_tracker_t* bw, uint32_t bytes, uint64_t elapsed_ms) {
    if (elapsed_ms == 0) elapsed_ms = 1;

    double rate = (double)bytes / ((double)elapsed_ms / 1000.0);

    bw->samples[bw->head] = rate;
    bw->head = (bw->head + 1) % BANDWIDTH_WINDOW_SIZE;
    if (bw->sample_count < BANDWIDTH_WINDOW_SIZE) {
        bw->sample_count++;
    }

    bw->current_bps = rate;
    bw->total_bytes += bytes;

    if (rate > bw->peak_bps) {
        bw->peak_bps = rate;
    }

    // Calculate moving average
    double sum = 0;
    for (int i = 0; i < bw->sample_count; i++) {
        sum += bw->samples[i];
    }
    bw->avg_bps = sum / bw->sample_count;
}

double bandwidth_get_rate(const bandwidth_tracker_t* bw) {
    return bw->avg_bps;
}

// ============================================
// TASK CREATION (assigns priority based on availability)
// ============================================

static task_priority_t calculate_priority(strategy_context_t* strategy,
                                           uint32_t chunk_index) {
    if (chunk_index >= strategy->total_chunks) return TASK_PRIORITY_NORMAL;

    uint32_t availability = strategy->chunks[chunk_index].availability;
    uint32_t retries = strategy->chunks[chunk_index].retry_count;

    // Boost priority for retried chunks
    if (retries >= 2) return TASK_PRIORITY_CRITICAL;

    // Priority based on availability
    if (availability <= 1) return TASK_PRIORITY_CRITICAL;
    if (availability <= 2) return TASK_PRIORITY_HIGH;
    if (availability <= 4) return TASK_PRIORITY_NORMAL;
    return TASK_PRIORITY_LOW;
}

static int schedule_chunk(scheduler_t* sched, uint32_t chunk_index,
                          const char* peer_id) {
    // Find peer info
    peer_source_t* peer = NULL;
    for (int i = 0; i < sched->strategy.peer_count; i++) {
        if (strcmp(sched->strategy.peers[i].peer_id, peer_id) == 0) {
            peer = &sched->strategy.peers[i];
            break;
        }
    }

    if (!peer) {
        LOG_WARN("Scheduler: Peer %s not found for chunk %u", peer_id, chunk_index);
        return -1;
    }

    download_task_t task;
    memset(&task, 0, sizeof(task));

    task.chunk_index = chunk_index;
    strncpy(task.peer_id, peer_id, MAX_ID_LENGTH - 1);
    strncpy(task.peer_ip, peer->ip, sizeof(task.peer_ip) - 1);
    task.peer_port = peer->port;
    task.peer_fd = peer->socket_fd;
    task.priority = calculate_priority(&sched->strategy, chunk_index);
    task.created_at = get_timestamp_ms();
    task.deadline = task.created_at + TRANSFER_TIMEOUT_MS;
    task.retry_count = sched->strategy.chunks[chunk_index].retry_count;

    // Mark in strategy
    strategy_mark_in_progress(&sched->strategy, chunk_index, peer_id);

    return pq_push(&sched->queue, &task);
}

// ============================================
// BANDWIDTH-AWARE PEER SELECTION
// ============================================

// Select best peer for a given chunk:
// 1. Must have the chunk
// 2. Must be connected
// 3. Prefer highest bandwidth
// 4. Penalize peers with many failures
static const char* select_best_peer(scheduler_t* sched, uint32_t chunk_index) {
    strategy_context_t* ctx = &sched->strategy;
    const char* best_peer = NULL;
    double best_score = -1.0;

    for (int i = 0; i < ctx->peer_count; i++) {
        peer_source_t* peer = &ctx->peers[i];

        if (!peer->connected) continue;

        // Check if peer has this chunk
        if (peer->chunk_bitmap && !peer->chunk_bitmap[chunk_index]) {
            continue;
        }

        // Calculate score: bandwidth - penalty for failures - penalty for load
        double score = peer->bandwidth_bps > 0 ? peer->bandwidth_bps : 100000.0;
        score -= (double)peer->failures * 50000.0;    // Penalty per failure
        score -= peer->active ? 25000.0 : 0;          // Penalty if already busy

        // Bonus for low latency
        if (peer->avg_latency_ms > 0 && peer->avg_latency_ms < 50) {
            score *= 1.2;
        }

        if (score > best_score) {
            best_score = score;
            best_peer = peer->peer_id;
        }
    }

    return best_peer;
}

// ============================================
// WORKER THREAD (downloads chunks from queue)
// ============================================

static int worker_download_chunk(download_worker_t* worker, download_task_t* task) {
    scheduler_t* sched = (scheduler_t*)worker->scheduler;
    (void)sched;

    int fd = task->peer_fd;
    if (fd < 0) {
        LOG_ERROR("Worker %d: No connection for peer %s", worker->id, task->peer_id);
        return -1;
    }

    task->request_sent_at = get_timestamp_ms();

    // Send chunk request
    message_t req;
    memset(&req, 0, sizeof(req));
    message_header_init(&req.header, MSG_CHUNK_REQUEST);

    payload_chunk_request_t* cr = (payload_chunk_request_t*)req.payload;
    memcpy(cr->file_hash, sched->file_hash, FILE_HASH_SIZE);
    cr->chunk_index = task->chunk_index;
    req.header.payload_length = sizeof(payload_chunk_request_t);

    ssize_t sent = send(fd, &req, message_total_size(&req), 0);
    if (sent <= 0) {
        LOG_ERROR("Worker %d: Failed to send chunk request %u",
                  worker->id, task->chunk_index);
        return -1;
    }

    // Receive chunk data
    uint8_t buffer[READ_BUFFER_SIZE];
    ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
    if (received <= 0) {
        LOG_ERROR("Worker %d: Failed to receive chunk %u",
                  worker->id, task->chunk_index);
        return -1;
    }

    task->response_received_at = get_timestamp_ms();

    message_t* resp = (message_t*)buffer;
    if (resp->header.type != MSG_CHUNK_DATA) {
        LOG_ERROR("Worker %d: Expected CHUNK_DATA, got %s",
                  worker->id, message_type_string(resp->header.type));
        return -1;
    }

    payload_chunk_data_t* cd = (payload_chunk_data_t*)resp->payload;

    // Verify chunk hash
    uint8_t computed_hash[FILE_HASH_SIZE];
    sha256_hash(cd->data, cd->chunk_size, computed_hash);
    if (memcmp(computed_hash, cd->chunk_hash, FILE_HASH_SIZE) != 0) {
        LOG_ERROR("Worker %d: Chunk %u hash mismatch!", worker->id, task->chunk_index);
        return -1;
    }

    // Write chunk to disk
    chunk_t chunk;
    memset(&chunk, 0, sizeof(chunk));
    chunk.index = cd->chunk_index;
    chunk.size = cd->chunk_size;
    memcpy(chunk.data, cd->data, cd->chunk_size);
    memcpy(chunk.hash, cd->chunk_hash, FILE_HASH_SIZE);

    if (chunk_write(sched->save_path, task->chunk_index, &chunk) != 0) {
        LOG_ERROR("Worker %d: Failed to write chunk %u", worker->id, task->chunk_index);
        return -1;
    }

    task->bytes_received = cd->chunk_size;
    return 0;
}

static void* worker_thread(void* arg) {
    download_worker_t* worker = (download_worker_t*)arg;
    scheduler_t* sched = (scheduler_t*)worker->scheduler;

    LOG_INFO("Worker %d: Started", worker->id);

    while (worker->running) {
        if (sched->paused) {
            usleep(100 * 1000);
            continue;
        }

        worker->idle = true;

        // Get next task from priority queue
        download_task_t task;
        if (pq_pop(&sched->queue, &task) != 0) {
            // Timeout or empty — check if we should stop
            if (!worker->running || sched->complete) break;
            continue;
        }

        worker->idle = false;
        worker->has_task = true;
        worker->current_task = task;

        LOG_DEBUG("Worker %d: Downloading chunk %u from %s (priority: %d)",
                  worker->id, task.chunk_index, task.peer_id, task.priority);

        // Execute download
        int result = worker_download_chunk(worker, &task);

        if (result == 0) {
            // Success
            strategy_mark_downloaded(&sched->strategy, task.chunk_index);

            uint64_t elapsed = task.response_received_at - task.request_sent_at;
            bandwidth_record(&sched->global_bandwidth, task.bytes_received, elapsed);

            strategy_update_peer_metrics(&sched->strategy, task.peer_id,
                (double)task.bytes_received / ((double)elapsed / 1000.0),
                (double)elapsed);

            pthread_mutex_lock(&sched->mutex);
            sched->completed_chunks++;

            if (sched->on_progress) {
                sched->on_progress(sched->completed_chunks, sched->total_chunks,
                                    bandwidth_get_rate(&sched->global_bandwidth),
                                    sched->callback_data);
            }

            // Check if complete
            if (sched->completed_chunks >= sched->total_chunks) {
                sched->complete = true;
                pthread_cond_broadcast(&sched->complete_cond);
            }

            pthread_mutex_unlock(&sched->mutex);
        } else {
            // Failed — requeue with higher priority
            strategy_mark_failed(&sched->strategy, task.chunk_index);
            strategy_record_peer_failure(&sched->strategy, task.peer_id);

            sched->total_retries++;

            if (task.retry_count < CHUNK_RETRY_COUNT) {
                // Try a different peer
                const char* new_peer = select_best_peer(sched, task.chunk_index);
                if (new_peer) {
                    sched->peer_switches++;
                    schedule_chunk(sched, task.chunk_index, new_peer);
                } else {
                    // Requeue to same peer
                    task.retry_count++;
                    task.priority = TASK_PRIORITY_CRITICAL;
                    task.created_at = get_timestamp_ms();
                    pq_push(&sched->queue, &task);
                }
            } else {
                LOG_ERROR("Worker %d: Chunk %u exceeded max retries (%d)",
                          worker->id, task.chunk_index, CHUNK_RETRY_COUNT);
            }
        }

        worker->has_task = false;
    }

    LOG_INFO("Worker %d: Stopped", worker->id);
    return NULL;
}

// ============================================
// SCHEDULER LIFECYCLE
// ============================================

int scheduler_init(scheduler_t* sched, strategy_type_t strategy,
                   uint32_t chunk_count, int max_parallel) {
    memset(sched, 0, sizeof(scheduler_t));

    if (strategy_init(&sched->strategy, strategy, chunk_count) != 0) {
        return -1;
    }

    pq_init(&sched->queue);
    pthread_mutex_init(&sched->mutex, NULL);
    pthread_cond_init(&sched->complete_cond, NULL);

    sched->total_chunks = chunk_count;
    sched->max_workers = max_parallel > MAX_ACTIVE_TRANSFERS ?
                         MAX_ACTIVE_TRANSFERS : max_parallel;
    sched->worker_count = 0;
    sched->running = false;
    sched->paused = false;
    sched->complete = false;

    bandwidth_init(&sched->global_bandwidth);

    LOG_INFO("Scheduler initialized: strategy=%s, chunks=%u, workers=%d",
             strategy_type_string(strategy), chunk_count, sched->max_workers);
    return 0;
}

void scheduler_cleanup(scheduler_t* sched) {
    scheduler_stop(sched);
    strategy_cleanup(&sched->strategy);
    pq_destroy(&sched->queue);
    pthread_mutex_destroy(&sched->mutex);
    pthread_cond_destroy(&sched->complete_cond);
    LOG_INFO("Scheduler cleaned up");
}

void scheduler_set_file_info(scheduler_t* sched, const uint8_t* file_hash,
                              const char* save_path) {
    memcpy(sched->file_hash, file_hash, FILE_HASH_SIZE);
    strncpy(sched->save_path, save_path, sizeof(sched->save_path) - 1);
}

void scheduler_set_callbacks(scheduler_t* sched,
    void (*on_progress)(uint32_t chunk, uint32_t total, double rate_bps, void* data),
    void (*on_complete)(bool success, uint64_t elapsed_ms, void* data),
    void* user_data) {
    sched->on_progress = on_progress;
    sched->on_complete = on_complete;
    sched->callback_data = user_data;
}

// ============================================
// PEER MANAGEMENT
// ============================================

int scheduler_add_peer(scheduler_t* sched, const char* peer_id,
                       const char* ip, uint16_t port, int fd) {
    int ret = strategy_add_peer(&sched->strategy, peer_id, ip, port);
    if (ret != 0) return ret;

    // Store socket fd
    for (int i = 0; i < sched->strategy.peer_count; i++) {
        if (strcmp(sched->strategy.peers[i].peer_id, peer_id) == 0) {
            sched->strategy.peers[i].socket_fd = fd;
            break;
        }
    }

    bandwidth_init(&sched->peer_bandwidth[sched->strategy.peer_count - 1]);

    LOG_INFO("Scheduler: Added peer %s (%s:%d, fd=%d)", peer_id, ip, port, fd);
    return 0;
}

int scheduler_remove_peer(scheduler_t* sched, const char* peer_id) {
    return strategy_remove_peer(&sched->strategy, peer_id);
}

// ============================================
// CONTROL
// ============================================

int scheduler_start(scheduler_t* sched) {
    pthread_mutex_lock(&sched->mutex);

    if (sched->running) {
        pthread_mutex_unlock(&sched->mutex);
        return 0;
    }

    sched->running = true;
    sched->started_at = get_timestamp_ms();

    // Populate initial queue: select chunks for each peer
    for (int p = 0; p < sched->strategy.peer_count; p++) {
        if (!sched->strategy.peers[p].connected) continue;

        const char* pid = sched->strategy.peers[p].peer_id;

        // Queue multiple chunks per peer for pipelining
        for (int q = 0; q < 4; q++) {
            int32_t chunk = strategy_select_next_chunk(&sched->strategy, pid);
            if (chunk < 0) break;
            schedule_chunk(sched, (uint32_t)chunk, pid);
        }
    }

    // Start worker threads
    sched->worker_count = sched->max_workers;
    for (int i = 0; i < sched->worker_count; i++) {
        sched->workers[i].id = i;
        sched->workers[i].running = true;
        sched->workers[i].idle = true;
        sched->workers[i].has_task = false;
        sched->workers[i].scheduler = sched;

        if (pthread_create(&sched->workers[i].thread, NULL,
                           worker_thread, &sched->workers[i]) != 0) {
            LOG_ERROR("Scheduler: Failed to create worker %d", i);
            sched->workers[i].running = false;
        }
    }

    pthread_mutex_unlock(&sched->mutex);

    LOG_INFO("Scheduler: Started with %d workers, %d queued tasks",
             sched->worker_count, sched->queue.count);
    return 0;
}

void scheduler_pause(scheduler_t* sched) {
    sched->paused = true;
    LOG_INFO("Scheduler: Paused");
}

void scheduler_resume(scheduler_t* sched) {
    sched->paused = false;

    // Re-queue chunks for idle workers
    pthread_mutex_lock(&sched->mutex);
    for (int p = 0; p < sched->strategy.peer_count; p++) {
        if (!sched->strategy.peers[p].connected) continue;
        const char* pid = sched->strategy.peers[p].peer_id;

        int32_t chunk = strategy_select_next_chunk(&sched->strategy, pid);
        if (chunk >= 0) {
            schedule_chunk(sched, (uint32_t)chunk, pid);
        }
    }
    pthread_mutex_unlock(&sched->mutex);

    LOG_INFO("Scheduler: Resumed");
}

void scheduler_stop(scheduler_t* sched) {
    pthread_mutex_lock(&sched->mutex);

    if (!sched->running) {
        pthread_mutex_unlock(&sched->mutex);
        return;
    }

    sched->running = false;

    // Signal all workers to wake up and exit
    for (int i = 0; i < sched->worker_count; i++) {
        sched->workers[i].running = false;
    }

    // Wake up anyone waiting on the queue
    pthread_mutex_lock(&sched->queue.mutex);
    pthread_cond_broadcast(&sched->queue.not_empty);
    pthread_mutex_unlock(&sched->queue.mutex);

    pthread_mutex_unlock(&sched->mutex);

    // Join worker threads
    for (int i = 0; i < sched->worker_count; i++) {
        pthread_join(sched->workers[i].thread, NULL);
    }

    sched->elapsed_ms = get_timestamp_ms() - sched->started_at;

    // Fire completion callback
    if (sched->on_complete) {
        sched->on_complete(sched->complete, sched->elapsed_ms,
                            sched->callback_data);
    }

    LOG_INFO("Scheduler: Stopped (completed=%u/%u, retries=%u, switches=%u, %.1fs)",
             sched->completed_chunks, sched->total_chunks,
             sched->total_retries, sched->peer_switches,
             (double)sched->elapsed_ms / 1000.0);
}

int scheduler_wait_complete(scheduler_t* sched, uint32_t timeout_ms) {
    pthread_mutex_lock(&sched->mutex);

    if (sched->complete) {
        pthread_mutex_unlock(&sched->mutex);
        return 0;
    }

    if (timeout_ms == 0) {
        // Wait indefinitely
        while (!sched->complete && sched->running) {
            pthread_cond_wait(&sched->complete_cond, &sched->mutex);
        }
    } else {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }

        while (!sched->complete && sched->running) {
            int ret = pthread_cond_timedwait(&sched->complete_cond,
                                              &sched->mutex, &ts);
            if (ret != 0) break; // Timeout
        }
    }

    bool ok = sched->complete;
    pthread_mutex_unlock(&sched->mutex);
    return ok ? 0 : -1;
}

// ============================================
// STATUS REPORTING
// ============================================

void scheduler_print_status(const scheduler_t* sched) {
    uint32_t completed, in_progress, remaining;
    strategy_get_stats(&sched->strategy, &completed, &in_progress, &remaining);

    double rate = bandwidth_get_rate(&sched->global_bandwidth);
    double peak = sched->global_bandwidth.peak_bps;
    uint64_t elapsed = sched->elapsed_ms > 0 ? sched->elapsed_ms :
                       (get_timestamp_ms() - sched->started_at);

    const char* rate_unit = "B/s";
    double rate_display = rate;
    if (rate > 1024 * 1024) {
        rate_display = rate / (1024 * 1024);
        rate_unit = "MB/s";
    } else if (rate > 1024) {
        rate_display = rate / 1024;
        rate_unit = "KB/s";
    }

    const char* peak_unit = "B/s";
    double peak_display = peak;
    if (peak > 1024 * 1024) {
        peak_display = peak / (1024 * 1024);
        peak_unit = "MB/s";
    } else if (peak > 1024) {
        peak_display = peak / 1024;
        peak_unit = "KB/s";
    }

    printf("\n");
    printf("╔════════════════════════════════════════════════════╗\n");
    printf("║              SCHEDULER STATUS                     ║\n");
    printf("╠════════════════════════════════════════════════════╣\n");
    printf("║  Strategy:    %-36s ║\n", strategy_type_string(sched->strategy.type));
    printf("║  Progress:    %u/%u chunks (%.1f%%)              \n",
           completed, sched->total_chunks, strategy_get_progress(&sched->strategy) * 100);
    printf("║  In Progress: %-36u ║\n", in_progress);
    printf("║  Remaining:   %-36u ║\n", remaining);
    printf("║  Queue Size:  %-36d ║\n", sched->queue.count);
    printf("╠════════════════════════════════════════════════════╣\n");
    printf("║  Speed:       %.1f %-30s ║\n", rate_display, rate_unit);
    printf("║  Peak:        %.1f %-30s ║\n", peak_display, peak_unit);
    printf("║  Elapsed:     %.1fs                              \n",
           (double)elapsed / 1000.0);
    printf("║  Retries:     %-36u ║\n", sched->total_retries);
    printf("║  Peer Switch: %-36u ║\n", sched->peer_switches);
    printf("╠════════════════════════════════════════════════════╣\n");
    printf("║  Workers:     %d/%d                              \n",
           sched->worker_count, sched->max_workers);

    for (int i = 0; i < sched->worker_count; i++) {
        const download_worker_t* w = &sched->workers[i];
        if (w->has_task) {
            printf("║    [%d] Chunk %-6u from %-20s  ║\n",
                   w->id, w->current_task.chunk_index, w->current_task.peer_id);
        } else {
            printf("║    [%d] idle                                  ║\n", w->id);
        }
    }

    printf("╠════════════════════════════════════════════════════╣\n");
    printf("║  Peers:       %-36d ║\n", sched->strategy.peer_count);

    for (int i = 0; i < sched->strategy.peer_count; i++) {
        const peer_source_t* p = &sched->strategy.peers[i];
        double bw = p->bandwidth_bps;
        const char* bw_unit = "B/s";
        if (bw > 1024 * 1024) {
            bw /= (1024 * 1024);
            bw_unit = "MB/s";
        } else if (bw > 1024) {
            bw /= 1024;
            bw_unit = "KB/s";
        }

        printf("║    %-16s %s  %.0f %s  lat=%.0fms  fail=%u\n",
               p->peer_id,
               p->connected ? "🟢" : "🔴",
               bw, bw_unit,
               p->avg_latency_ms,
               p->failures);
    }

    printf("╚════════════════════════════════════════════════════╝\n");
}