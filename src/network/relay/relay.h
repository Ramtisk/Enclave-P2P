#ifndef P2P_RELAY_H
#define P2P_RELAY_H

#include "relay_types.h"
#include "relay_dispatch.h"
#include "relay_handlers_basic.h"
#include "relay_handlers_group.h"
#include "relay_handlers_file.h"
#include "relay_handlers_nat.h"

/*  ============================================
    RELAY SERVER TOP-LEVEL API

    Note: Lifecycle + accept loop only.
    Message handling is in relay_dispatch + handler files.
    ============================================ */

int  relay_init(relay_server_t* server, uint16_t port);
int  relay_start(relay_server_t* server);
void relay_stop(relay_server_t* server);
void relay_cleanup(relay_server_t* server);

int  relay_accept_client(relay_server_t* server);
void relay_disconnect_client(relay_server_t* server, int client_index);

#endif // P2P_RELAY_H