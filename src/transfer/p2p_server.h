#ifndef P2P_SERVER_H
#define P2P_SERVER_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "transfer_context.h"
#include "file_manager.h"
#include "../common/config.h"

typedef struct {
    int server_fd;
    uint16_t port;
    bool running;
    pthread_t accept_thread;
    transfer_context_t* send_transfers[MAX_ACTIVE_TRANSFERS];
    int send_count;
    pthread_mutex_t send_mutex;
} p2p_server_t;

int p2p_server_init(p2p_server_t* server, uint16_t port);
int p2p_server_start(p2p_server_t* server, file_manager_t* file_mgr);
void p2p_server_stop(p2p_server_t* server);
void p2p_server_cleanup(p2p_server_t* server);

#endif