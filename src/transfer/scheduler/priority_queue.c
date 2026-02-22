#include "priority_queue.h"
#include "../../common/logging.h"
#include <string.h>
#include <time.h>

static bool task_less_than(const download_task_t* a, const download_task_t* b) {
    if (a->priority != b->priority) return a->priority < b->priority;
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
        } else break;
    }
}

static void pq_sift_down(priority_queue_t* pq, int index) {
    int size = pq->count;
    while (1) {
        int smallest = index, left = 2*index+1, right = 2*index+2;
        if (left < size && task_less_than(&pq->tasks[left], &pq->tasks[smallest])) smallest = left;
        if (right < size && task_less_than(&pq->tasks[right], &pq->tasks[smallest])) smallest = right;
        if (smallest != index) { pq_swap(pq, index, smallest); index = smallest; }
        else break;
    }
}

void pq_init(priority_queue_t* pq) {
    memset(pq, 0, sizeof(priority_queue_t));
    pthread_mutex_init(&pq->mutex, NULL);
    pthread_cond_init(&pq->not_empty, NULL);
}

void pq_destroy(priority_queue_t* pq) {
    pthread_mutex_destroy(&pq->mutex);
    pthread_cond_destroy(&pq->not_empty);
}

int pq_push(priority_queue_t* pq, const download_task_t* task) {
    pthread_mutex_lock(&pq->mutex);
    if (pq->count >= SCHEDULER_MAX_QUEUE) {
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
    while (pq->count == 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;
        if (pthread_cond_timedwait(&pq->not_empty, &pq->mutex, &ts) != 0) {
            pthread_mutex_unlock(&pq->mutex);
            return -1;
        }
    }
    *task_out = pq->tasks[0];
    pq->count--;
    if (pq->count > 0) { pq->tasks[0] = pq->tasks[pq->count]; pq_sift_down(pq, 0); }
    pthread_mutex_unlock(&pq->mutex);
    return 0;
}

int pq_peek(const priority_queue_t* pq, download_task_t* task_out) {
    if (pq->count == 0) return -1;
    *task_out = pq->tasks[0];
    return 0;
}

bool pq_is_empty(const priority_queue_t* pq) {
    return pq->count == 0;
}