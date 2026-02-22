#ifndef P2P_CRYPTO_HYBRID_UTILS_H
#define P2P_CRYPTO_HYBRID_UTILS_H

#include "hybrid_types.h"

/*  ============================================
    HYBRID UTILITY API

    Note: Utility functions for hybrid handshake state and PQC availability.
    ============================================ */
const char* hybrid_state_string(hybrid_state_t state);

#endif