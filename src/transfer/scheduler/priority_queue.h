#ifndef P2P_PRIORITY_QUEUE_H
#define P2P_PRIORITY_QUEUE_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "scheduler_types.h"

void pq_init(priority_queue_t* pq);
void pq_destroy(priority_queue_t* pq);
int pq_push(priority_queue_t* pq, const download_task_t* task);
int pq_pop(priority_queue_t* pq, download_task_t* task_out);
int pq_peek(const priority_queue_t* pq, download_task_t* task_out);
bool pq_is_empty(const priority_queue_t* pq);

#endif