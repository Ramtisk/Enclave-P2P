#ifndef P2P_SCHEDULER_PEERS_H
#define P2P_SCHEDULER_PEERS_H

#include "scheduler_types.h"

int scheduler_add_peer(scheduler_t* sched, const char* peer_id,
                       const char* ip, uint16_t port, int fd);
int scheduler_remove_peer(scheduler_t* sched, const char* peer_id);
const char* select_best_peer(scheduler_t* sched, uint32_t chunk_index);
task_priority_t calculate_priority(strategy_context_t* strategy, uint32_t chunk_index);
int schedule_chunk(scheduler_t* sched, uint32_t chunk_index, const char* peer_id);

#endif