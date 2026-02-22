#ifndef P2P_ERASURE_PRINT_H
#define P2P_ERASURE_PRINT_H

#include "erasure_types.h"

/*  ============================================
    ERASURE PRINT API

    Note: Debug/display functions for codec info and shard status.
    ============================================ */
void erasure_print_info(const erasure_codec_t* codec);
void erasure_print_status(const erasure_encoded_t* enc);

#endif