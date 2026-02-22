#ifndef P2P_IDENTITY_PRINT_H
#define P2P_IDENTITY_PRINT_H

#include "identity_types.h"

/*  ============================================
    IDENTITY PRINT API

    Note: Debug/display functions for printing peer and group
    identity information in a human-readable format.
    ============================================ */
void identity_print(const peer_identity_t *id);
void identity_print_group(const group_identity_t *gid);

#endif