#ifndef P2P_DHT_PRINT_H
#define P2P_DHT_PRINT_H

#include "dht_types.h"

/*  ============================================
    DHT PRINT/UTILITY API

    Note: Status display and message type string conversion.
    ============================================ */

const char* dht_msg_type_string(dht_msg_type_t type);
void dht_print_status(const dht_context_t* ctx);

#endif // P2P_DHT_PRINT_H