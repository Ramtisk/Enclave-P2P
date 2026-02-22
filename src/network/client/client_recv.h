#ifndef P2P_CLIENT_RECV_H
#define P2P_CLIENT_RECV_H

#include "client_types.h"

/*  ============================================
    CLIENT RECEIVE THREAD + MESSAGE DISPATCH

    Note: The receive thread reads from the relay socket and dispatches
    incoming messages to the appropriate internal handler or user callback.
    ============================================ */

// Entry point for the receive thread (pthread start_routine).
void* client_recv_thread(void* arg);

// Entry point for the auto-ping thread.
void* client_ping_thread(void* arg);

#endif // P2P_CLIENT_RECV_H