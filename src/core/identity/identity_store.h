#ifndef P2P_IDENTITY_STORE_H
#define P2P_IDENTITY_STORE_H

#include "identity_types.h"

/*  ============================================
    IDENTITY STORE API

    Note: Functions for initializing, saving, loading, and managing
    the persistent identity store on disk.
    ============================================ */
int identity_store_init(identity_store_t *store, const char *storage_path);
void identity_store_cleanup(identity_store_t *store);
int identity_store_save(const identity_store_t *store);
int identity_store_load(identity_store_t *store);
group_identity_t *identity_store_find_group(identity_store_t *store,
                                            const char *group_id);
int identity_store_remove_group(identity_store_t *store,
                                const char *group_id);

#endif