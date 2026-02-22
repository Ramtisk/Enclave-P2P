#ifndef P2P_SCHEDULER_TYPES_H
#define P2P_SCHEDULER_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "../strategy/strategy.h"
#include "../chunking.h"
#include "../../common/config.h"

typedef enum {
    TASK_PRIORITY_CRITICAL = 0,
    TASK_PRIORITY_HIGH     = 1,
    TASK_PRIORITY_NORMAL   = 2,
    TASK_PRIORITY_LOW      = 3,
    TASK_PRIORITY_COUNT    = 4
} task_priority_t;

typedef struct {
    uint32_t chunk_index;
    char peer_id[MAX_ID_LENGTH];
    char peer_ip[46];
    uint16_t peer_port;
    int peer_fd;
    task_priority_t priority;
    uint64_t created_at;
    uint64_t deadline;
    uint32_t retry_count;
    uint64_t request_sent_at;
    uint64_t response_received_at;
    uint32_t bytes_received;
} download_task_t;

typedef struct {
    int id;
    pthread_t thread;
    bool running;
    bool idle;
    download_task_t current_task;
    bool has_task;
    void* scheduler;
} download_worker_t;

#define SCHEDULER_MAX_QUEUE 512

typedef struct {
    download_task_t tasks[SCHEDULER_MAX_QUEUE];
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
} priority_queue_t;

#define BANDWIDTH_WINDOW_SIZE 16

typedef struct {
    double samples[BANDWIDTH_WINDOW_SIZE];
    int sample_count;
    int head;
    double current_bps;
    double peak_bps;
    double avg_bps;
    uint64_t total_bytes;
    uint64_t started_at;
} bandwidth_tracker_t;

typedef struct {
    strategy_context_t strategy;
    priority_queue_t queue;
    download_worker_t workers[MAX_ACTIVE_TRANSFERS];
    int worker_count;
    int max_workers;
    uint8_t file_hash[FILE_HASH_SIZE];
    char save_path[1024];
    uint32_t total_chunks;
    uint32_t completed_chunks;
    bandwidth_tracker_t global_bandwidth;
    bandwidth_tracker_t peer_bandwidth[MAX_GROUP_MEMBERS];
    bool running;
    bool paused;
    bool complete;
    pthread_mutex_t mutex;
    pthread_cond_t complete_cond;
    void (*on_progress)(uint32_t chunk, uint32_t total, double rate_bps, void* data);
    void (*on_complete)(bool success, uint64_t elapsed_ms, void* data);
    void (*on_peer_connected)(const char* peer_id, void* data);
    void* callback_data;
    uint64_t started_at;
    uint64_t elapsed_ms;
    uint32_t total_retries;
    uint32_t peer_switches;
} scheduler_t;

#endif