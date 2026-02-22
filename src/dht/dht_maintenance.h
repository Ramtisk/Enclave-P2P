#ifndef P2P_DHT_MAINTENANCE_H
#define P2P_DHT_MAINTENANCE_H

#include "dht_types.h"

/*  ============================================
    DHT MAINTENANCE API

    Note: Background thread that performs periodic housekeeping:
    - Expires pending requests
    - Expires storage entries
    - Pings stale nodes and removes dead ones
    - Republishes values
    - Refreshes empty buckets
    ============================================ */

// Entry point for the maintenance thread.
// Pass as the start_routine to pthread_create with ctx as arg.
void* dht_maintenance_thread(void* arg);

#endif // P2P_DHT_MAINTENANCE_H