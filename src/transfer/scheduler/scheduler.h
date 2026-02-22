#ifndef P2P_SCHEDULER_H
#define P2P_SCHEDULER_H

#include "scheduler_types.h"
#include "scheduler_peers.h"
#include "priority_queue.h"
#include "bandwidth.h"

int scheduler_init(scheduler_t* sched, strategy_type_t strategy,
                   uint32_t chunk_count, int max_parallel);
void scheduler_cleanup(scheduler_t* sched);

void scheduler_set_file_info(scheduler_t* sched, const uint8_t* file_hash, const char* save_path);
void scheduler_set_callbacks(scheduler_t* sched,
    void (*on_progress)(uint32_t chunk, uint32_t total, double rate_bps, void* data),
    void (*on_complete)(bool success, uint64_t elapsed_ms, void* data),
    void* user_data);

int scheduler_start(scheduler_t* sched);
void scheduler_pause(scheduler_t* sched);
void scheduler_resume(scheduler_t* sched);
void scheduler_stop(scheduler_t* sched);
int scheduler_wait_complete(scheduler_t* sched, uint32_t timeout_ms);

void scheduler_print_status(const scheduler_t* sched);

#endif