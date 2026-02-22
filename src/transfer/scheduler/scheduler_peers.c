#include "scheduler_peers.h"
#include "priority_queue.h"
#include "bandwidth.h"
#include "../../common/logging.h"

#include <string.h>
#include <time.h>

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

task_priority_t calculate_priority(strategy_context_t* strategy, uint32_t chunk_index) {
    if (chunk_index >= strategy->total_chunks) return TASK_PRIORITY_NORMAL;
    uint32_t availability = strategy->chunks[chunk_index].availability;
    uint32_t retries = strategy->chunks[chunk_index].retry_count;
    if (retries >= 2) return TASK_PRIORITY_CRITICAL;
    if (availability <= 1) return TASK_PRIORITY_CRITICAL;
    if (availability <= 2) return TASK_PRIORITY_HIGH;
    if (availability <= 4) return TASK_PRIORITY_NORMAL;
    return TASK_PRIORITY_LOW;
}

int schedule_chunk(scheduler_t* sched, uint32_t chunk_index, const char* peer_id) {
    peer_source_t* peer = NULL;
    for (int i = 0; i < sched->strategy.peer_count; i++) {
        if (strcmp(sched->strategy.peers[i].peer_id, peer_id) == 0) {
            peer = &sched->strategy.peers[i];
            break;
        }
    }
    if (!peer) return -1;

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
    strategy_mark_in_progress(&sched->strategy, chunk_index, peer_id);
    return pq_push(&sched->queue, &task);
}

const char* select_best_peer(scheduler_t* sched, uint32_t chunk_index) {
    strategy_context_t* ctx = &sched->strategy;
    const char* best_peer = NULL;
    double best_score = -1.0;

    for (int i = 0; i < ctx->peer_count; i++) {
        peer_source_t* peer = &ctx->peers[i];
        if (!peer->connected) continue;
        if (peer->chunk_bitmap && !peer->chunk_bitmap[chunk_index]) continue;
        double score = peer->bandwidth_bps > 0 ? peer->bandwidth_bps : 100000.0;
        score -= (double)peer->failures * 50000.0;
        score -= peer->active ? 25000.0 : 0;
        if (peer->avg_latency_ms > 0 && peer->avg_latency_ms < 50) score *= 1.2;
        if (score > best_score) { best_score = score; best_peer = peer->peer_id; }
    }
    return best_peer;
}

int scheduler_add_peer(scheduler_t* sched, const char* peer_id,
                       const char* ip, uint16_t port, int fd) {
    int ret = strategy_add_peer(&sched->strategy, peer_id, ip, port);
    if (ret != 0) return ret;
    for (int i = 0; i < sched->strategy.peer_count; i++) {
        if (strcmp(sched->strategy.peers[i].peer_id, peer_id) == 0) {
            sched->strategy.peers[i].socket_fd = fd;
            break;
        }
    }
    bandwidth_init(&sched->peer_bandwidth[sched->strategy.peer_count - 1]);
    return 0;
}

int scheduler_remove_peer(scheduler_t* sched, const char* peer_id) {
    return strategy_remove_peer(&sched->strategy, peer_id);
}