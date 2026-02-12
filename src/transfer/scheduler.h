#ifndef P2P_SCHEDULER_H
#define P2P_SCHEDULER_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "strategy/strategy.h"
#include "chunking.h"
#include "../common/config.h"

// ============================================
// PRIORITY QUEUE ENTRY
// ============================================
typedef enum {
    TASK_PRIORITY_CRITICAL = 0, // Rarest chunk, single source
    TASK_PRIORITY_HIGH     = 1, // Rarest chunk, few sources
    TASK_PRIORITY_NORMAL   = 2, // Regular chunk
    TASK_PRIORITY_LOW      = 3, // Common chunk, many sources
    TASK_PRIORITY_COUNT    = 4
} task_priority_t;

typedef struct {
    uint32_t chunk_index;
    char peer_id[MAX_ID_LENGTH];
    char peer_ip[46];
    uint16_t peer_port;
    int peer_fd;                    // -1 if not connected

    task_priority_t priority;
    uint64_t created_at;
    uint64_t deadline;              // Must complete by this time
    uint32_t retry_count;

    // Transfer metrics for this task
    uint64_t request_sent_at;
    uint64_t response_received_at;
    uint32_t bytes_received;
} download_task_t;

// ============================================
// DOWNLOAD WORKER
// ============================================
typedef struct {
    int id;
    pthread_t thread;
    bool running;
    bool idle;

    // Currently executing task
    download_task_t current_task;
    bool has_task;

    // Back-reference
    void* scheduler;    // scheduler_t*
} download_worker_t;

// ============================================
// PRIORITY QUEUE (min-heap by priority then creation time)
// ============================================
#define SCHEDULER_MAX_QUEUE 512

typedef struct {
    download_task_t tasks[SCHEDULER_MAX_QUEUE];
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;       // Signal when task added
} priority_queue_t;

// ============================================
// BANDWIDTH TRACKER
// ============================================
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

// ============================================
// SCHEDULER
// ============================================
typedef struct {
    // Strategy engine
    strategy_context_t strategy;

    // Priority queue
    priority_queue_t queue;

    // Worker threads for parallel downloads
    download_worker_t workers[MAX_ACTIVE_TRANSFERS];
    int worker_count;
    int max_workers;

    // Transfer info
    uint8_t file_hash[FILE_HASH_SIZE];
    char save_path[1024];
    uint32_t total_chunks;
    uint32_t completed_chunks;

    // Bandwidth tracking (global and per-peer)
    bandwidth_tracker_t global_bandwidth;
    bandwidth_tracker_t peer_bandwidth[MAX_GROUP_MEMBERS];

    // State
    bool running;
    bool paused;
    bool complete;
    pthread_mutex_t mutex;
    pthread_cond_t complete_cond;   // Signal when transfer complete

    // Callbacks
    void (*on_progress)(uint32_t chunk, uint32_t total, double rate_bps, void* data);
    void (*on_complete)(bool success, uint64_t elapsed_ms, void* data);
    void (*on_peer_connected)(const char* peer_id, void* data);
    void* callback_data;

    // Statistics
    uint64_t started_at;
    uint64_t elapsed_ms;
    uint32_t total_retries;
    uint32_t peer_switches;         // How many times we switched peers for a chunk
} scheduler_t;

// ============================================
// API
// ============================================

// Lifecycle
int scheduler_init(scheduler_t* sched, strategy_type_t strategy,
                   uint32_t chunk_count, int max_parallel);
void scheduler_cleanup(scheduler_t* sched);

// Configuration
void scheduler_set_file_info(scheduler_t* sched, const uint8_t* file_hash,
                              const char* save_path);
void scheduler_set_callbacks(scheduler_t* sched,
    void (*on_progress)(uint32_t chunk, uint32_t total, double rate_bps, void* data),
    void (*on_complete)(bool success, uint64_t elapsed_ms, void* data),
    void* user_data);

// Peer management
int scheduler_add_peer(scheduler_t* sched, const char* peer_id,
                       const char* ip, uint16_t port, int fd);
int scheduler_remove_peer(scheduler_t* sched, const char* peer_id);

// Control
int scheduler_start(scheduler_t* sched);
void scheduler_pause(scheduler_t* sched);
void scheduler_resume(scheduler_t* sched);
void scheduler_stop(scheduler_t* sched);
int scheduler_wait_complete(scheduler_t* sched, uint32_t timeout_ms);

// Priority queue
int pq_push(priority_queue_t* pq, const download_task_t* task);
int pq_pop(priority_queue_t* pq, download_task_t* task_out);
int pq_peek(const priority_queue_t* pq, download_task_t* task_out);
bool pq_is_empty(const priority_queue_t* pq);

// Bandwidth tracking
void bandwidth_init(bandwidth_tracker_t* bw);
void bandwidth_record(bandwidth_tracker_t* bw, uint32_t bytes, uint64_t elapsed_ms);
double bandwidth_get_rate(const bandwidth_tracker_t* bw);

// Query
void scheduler_print_status(const scheduler_t* sched);

#endif // P2P_SCHEDULER_H