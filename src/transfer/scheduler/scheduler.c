#include "scheduler.h"
#include "scheduler_worker.h"
#include "scheduler_peers.h"
#include "priority_queue.h"
#include "bandwidth.h"
#include "../../common/logging.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int scheduler_init(scheduler_t* sched, strategy_type_t strategy,
                   uint32_t chunk_count, int max_parallel) {
    memset(sched, 0, sizeof(scheduler_t));
    if (strategy_init(&sched->strategy, strategy, chunk_count) != 0) return -1;
    pq_init(&sched->queue);
    pthread_mutex_init(&sched->mutex, NULL);
    pthread_cond_init(&sched->complete_cond, NULL);
    sched->total_chunks = chunk_count;
    sched->max_workers = max_parallel > MAX_ACTIVE_TRANSFERS ? MAX_ACTIVE_TRANSFERS : max_parallel;
    bandwidth_init(&sched->global_bandwidth);
    return 0;
}

void scheduler_cleanup(scheduler_t* sched) {
    scheduler_stop(sched);
    strategy_cleanup(&sched->strategy);
    pq_destroy(&sched->queue);
    pthread_mutex_destroy(&sched->mutex);
    pthread_cond_destroy(&sched->complete_cond);
}

void scheduler_set_file_info(scheduler_t* sched, const uint8_t* file_hash, const char* save_path) {
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

int scheduler_start(scheduler_t* sched) {
    pthread_mutex_lock(&sched->mutex);
    if (sched->running) { pthread_mutex_unlock(&sched->mutex); return 0; }
    sched->running = true;
    sched->started_at = get_timestamp_ms();

    for (int p = 0; p < sched->strategy.peer_count; p++) {
        if (!sched->strategy.peers[p].connected) continue;
        const char* pid = sched->strategy.peers[p].peer_id;
        for (int q = 0; q < 4; q++) {
            int32_t chunk = strategy_select_next_chunk(&sched->strategy, pid);
            if (chunk < 0) break;
            schedule_chunk(sched, (uint32_t)chunk, pid);
        }
    }

    sched->worker_count = sched->max_workers;
    for (int i = 0; i < sched->worker_count; i++) {
        sched->workers[i].id = i;
        sched->workers[i].running = true;
        sched->workers[i].idle = true;
        sched->workers[i].has_task = false;
        sched->workers[i].scheduler = sched;
        if (pthread_create(&sched->workers[i].thread, NULL, worker_thread, &sched->workers[i]) != 0)
            sched->workers[i].running = false;
    }
    pthread_mutex_unlock(&sched->mutex);
    return 0;
}

void scheduler_pause(scheduler_t* sched) { sched->paused = true; }

void scheduler_resume(scheduler_t* sched) {
    sched->paused = false;
    pthread_mutex_lock(&sched->mutex);
    for (int p = 0; p < sched->strategy.peer_count; p++) {
        if (!sched->strategy.peers[p].connected) continue;
        int32_t chunk = strategy_select_next_chunk(&sched->strategy, sched->strategy.peers[p].peer_id);
        if (chunk >= 0) schedule_chunk(sched, (uint32_t)chunk, sched->strategy.peers[p].peer_id);
    }
    pthread_mutex_unlock(&sched->mutex);
}

void scheduler_stop(scheduler_t* sched) {
    pthread_mutex_lock(&sched->mutex);
    if (!sched->running) { pthread_mutex_unlock(&sched->mutex); return; }
    sched->running = false;
    for (int i = 0; i < sched->worker_count; i++) sched->workers[i].running = false;
    pthread_mutex_lock(&sched->queue.mutex);
    pthread_cond_broadcast(&sched->queue.not_empty);
    pthread_mutex_unlock(&sched->queue.mutex);
    pthread_mutex_unlock(&sched->mutex);
    for (int i = 0; i < sched->worker_count; i++) pthread_join(sched->workers[i].thread, NULL);
    sched->elapsed_ms = get_timestamp_ms() - sched->started_at;
    if (sched->on_complete) sched->on_complete(sched->complete, sched->elapsed_ms, sched->callback_data);
}

int scheduler_wait_complete(scheduler_t* sched, uint32_t timeout_ms) {
    pthread_mutex_lock(&sched->mutex);
    if (sched->complete) { pthread_mutex_unlock(&sched->mutex); return 0; }
    if (timeout_ms == 0) {
        while (!sched->complete && sched->running)
            pthread_cond_wait(&sched->complete_cond, &sched->mutex);
    } else {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000;
        if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
        while (!sched->complete && sched->running)
            if (pthread_cond_timedwait(&sched->complete_cond, &sched->mutex, &ts) != 0) break;
    }
    bool ok = sched->complete;
    pthread_mutex_unlock(&sched->mutex);
    return ok ? 0 : -1;
}

void scheduler_print_status(const scheduler_t* sched) {
    uint32_t completed, in_progress, remaining;
    strategy_get_stats(&sched->strategy, &completed, &in_progress, &remaining);
    double rate = bandwidth_get_rate(&sched->global_bandwidth);
    double peak = sched->global_bandwidth.peak_bps;
    uint64_t elapsed = sched->elapsed_ms > 0 ? sched->elapsed_ms : (get_timestamp_ms() - sched->started_at);

    const char* ru = "B/s"; double rd = rate;
    if (rate > 1024*1024) { rd = rate/(1024*1024); ru = "MB/s"; }
    else if (rate > 1024) { rd = rate/1024; ru = "KB/s"; }
    const char* pu = "B/s"; double pd = peak;
    if (peak > 1024*1024) { pd = peak/(1024*1024); pu = "MB/s"; }
    else if (peak > 1024) { pd = peak/1024; pu = "KB/s"; }

    printf("\n╔════════════════════════════════════════════════════╗\n");
    printf("║              SCHEDULER STATUS                     ║\n");
    printf("╠════════════════════════════════════════════════════╣\n");
    printf("║  Strategy:    %-36s ║\n", strategy_type_string(sched->strategy.type));
    printf("║  Progress:    %u/%u chunks (%.1f%%)\n", completed, sched->total_chunks, strategy_get_progress(&sched->strategy)*100);
    printf("║  In Progress: %-36u ║\n", in_progress);
    printf("║  Remaining:   %-36u ║\n", remaining);
    printf("║  Queue Size:  %-36d ║\n", sched->queue.count);
    printf("╠════════════════════════════════════════════════════╣\n");
    printf("║  Speed:       %.1f %-30s ║\n", rd, ru);
    printf("║  Peak:        %.1f %-30s ║\n", pd, pu);
    printf("║  Elapsed:     %.1fs\n", (double)elapsed/1000.0);
    printf("║  Retries:     %-36u ║\n", sched->total_retries);
    printf("║  Peer Switch: %-36u ║\n", sched->peer_switches);
    printf("╠════════════════════════════════════════════════════╣\n");
    printf("║  Workers:     %d/%d\n", sched->worker_count, sched->max_workers);
    for (int i = 0; i < sched->worker_count; i++) {
        const download_worker_t* w = &sched->workers[i];
        if (w->has_task) printf("║    [%d] Chunk %-6u from %-20s  ║\n", w->id, w->current_task.chunk_index, w->current_task.peer_id);
        else printf("║    [%d] idle                                  ║\n", w->id);
    }
    printf("╠════════════════════════════════════════════════════╣\n");
    printf("║  Peers:       %-36d ║\n", sched->strategy.peer_count);
    for (int i = 0; i < sched->strategy.peer_count; i++) {
        const peer_source_t* p = &sched->strategy.peers[i];
        double bw = p->bandwidth_bps; const char* bu = "B/s";
        if (bw > 1024*1024) { bw /= 1024*1024; bu = "MB/s"; }
        else if (bw > 1024) { bw /= 1024; bu = "KB/s"; }
        printf("║    %-16s %s  %.0f %s  lat=%.0fms  fail=%u\n",
               p->peer_id, p->connected?"🟢":"🔴", bw, bu, p->avg_latency_ms, p->failures);
    }
    printf("╚════════════════════════════════════════════════════╝\n");
}