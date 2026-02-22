#define _POSIX_C_SOURCE 200809L
#include "identity_store.h"
#include "identity_peer.h"
#include "identity_helpers.h"
#include "../../crypto/classic.h"
#include "../../crypto/hashing.h"
#include "../../common/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

extern void sha256_hash(const uint8_t *data, size_t len, uint8_t *hash_out);

/*  Function: identity_store_init
    Description:
    Initializes the identity store. Tries to load an existing identity from disk.
    If none found, generates a new long-term identity and saves it.

    Parameters:
    - store: Pointer to the identity_store_t structure.
    - storage_path: File path for persistent storage (can be NULL for in-memory only).

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Clears the store structure.
    2. Sets the storage path if provided.
    3. Tries to load an existing identity from disk.
    4. If loading fails, generates a new identity.
    5. Marks the store as loaded.
    6. Saves the identity to disk if a path is provided.
*/
int identity_store_init(identity_store_t *store, const char *storage_path)
{
    if (!store)
        return -1;

    memset(store, 0, sizeof(identity_store_t));

    if (storage_path)
    {
        strncpy(store->storage_path, storage_path, sizeof(store->storage_path) - 1);
    }

    if (storage_path && identity_store_load(store) == 0)
    {
        LOG_INFO("identity: Loaded existing identity: %s", store->self.peer_id);
        return 0;
    }

    if (identity_generate(&store->self) != 0)
    {
        return -1;
    }

    store->loaded = true;

    if (storage_path)
    {
        identity_store_save(store);
    }

    return 0;
}

/*  Function: identity_store_cleanup
    Description:
    Securely cleans up the identity store by zeroing all secret keys.

    Parameters:
    - store: Pointer to the identity_store_t structure.

    Steps:
    1. Zeros the long-term secret key.
    2. Zeros all group ephemeral secret keys (sign and kx).
    3. Marks the store as not loaded.
    4. Logs the cleanup event.
*/
void identity_store_cleanup(identity_store_t *store)
{
    if (!store)
        return;

    p2p_memzero(store->self.sign_sk, sizeof(store->self.sign_sk));

    for (int i = 0; i < store->group_count; i++)
    {
        p2p_memzero(store->groups[i].sign_sk, sizeof(store->groups[i].sign_sk));
        p2p_memzero(store->groups[i].kx_sk, sizeof(store->groups[i].kx_sk));
    }

    store->loaded = false;
    LOG_DEBUG("identity: Store cleaned up");
}

/*  Function: identity_store_save
    Description:
    Saves the identity store to disk in binary format.

    Parameters:
    - store: Pointer to the identity_store_t structure.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Opens the storage file for writing.
    2. Writes magic number (0x49444E54 = "IDNT") and version.
    3. Writes long-term public key, secret key, and creation timestamp.
    4. Writes group count and all group identity data.
    5. Closes the file and logs the event.
*/
int identity_store_save(const identity_store_t *store)
{
    if (!store || !store->storage_path[0])
        return -1;

    FILE *f = fopen(store->storage_path, "wb");
    if (!f)
    {
        LOG_WARN("identity: Cannot save to %s", store->storage_path);
        return -1;
    }

    uint32_t magic = 0x49444E54;
    uint8_t version = IDENTITY_VERSION;
    fwrite(&magic, 4, 1, f);
    fwrite(&version, 1, 1, f);

    fwrite(store->self.sign_pk, CRYPTO_SIGN_PK_SIZE, 1, f);
    fwrite(store->self.sign_sk, CRYPTO_SIGN_SK_SIZE, 1, f);
    fwrite(&store->self.created_at, sizeof(uint64_t), 1, f);

    int32_t gc = store->group_count;
    fwrite(&gc, sizeof(int32_t), 1, f);

    for (int i = 0; i < store->group_count; i++)
    {
        const group_identity_t *g = &store->groups[i];
        fwrite(g->group_id, MAX_ID_LENGTH, 1, f);
        fwrite(g->sign_pk, CRYPTO_SIGN_PK_SIZE, 1, f);
        fwrite(g->sign_sk, CRYPTO_SIGN_SK_SIZE, 1, f);
        fwrite(g->kx_pk, CRYPTO_KX_PK_SIZE, 1, f);
        fwrite(g->kx_sk, CRYPTO_KX_SK_SIZE, 1, f);
        fwrite(g->binding_sig, CRYPTO_SIGN_SIZE, 1, f);
        fwrite(&g->created_at, sizeof(uint64_t), 1, f);
    }

    fclose(f);

    LOG_INFO("identity: Saved to %s (%d group identities)",
             store->storage_path, store->group_count);
    return 0;
}

/*  Function: identity_store_load
    Description:
    Loads the identity store from disk.

    Parameters:
    - store: Pointer to the identity_store_t structure.

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Opens the storage file for reading.
    2. Reads and validates magic number and version.
    3. Reads long-term public key, secret key, and creation timestamp.
    4. Derives peer ID and fingerprint from the loaded public key.
    5. Reads group count and all group identity data.
    6. Derives ephemeral fingerprint and ID for each group.
    7. Marks the store as loaded and closes the file.
*/
int identity_store_load(identity_store_t *store)
{
    if (!store || !store->storage_path[0])
        return -1;

    FILE *f = fopen(store->storage_path, "rb");
    if (!f)
        return -1;

    uint32_t magic;
    uint8_t version;
    if (fread(&magic, 4, 1, f) != 1 || magic != 0x49444E54)
    {
        fclose(f);
        return -1;
    }
    if (fread(&version, 1, 1, f) != 1 || version != IDENTITY_VERSION)
    {
        fclose(f);
        return -1;
    }

    if (fread(store->self.sign_pk, CRYPTO_SIGN_PK_SIZE, 1, f) != 1 ||
        fread(store->self.sign_sk, CRYPTO_SIGN_SK_SIZE, 1, f) != 1 ||
        fread(&store->self.created_at, sizeof(uint64_t), 1, f) != 1)
    {
        fclose(f);
        return -1;
    }

    store->self.version = version;
    store->self.initialized = true;
    identity_derive_id(&store->self);

    int32_t gc;
    if (fread(&gc, sizeof(int32_t), 1, f) != 1)
    {
        fclose(f);
        store->loaded = true;
        return 0;
    }

    if (gc > MAX_GROUP_IDENTITIES)
        gc = MAX_GROUP_IDENTITIES;
    store->group_count = gc;

    for (int i = 0; i < gc; i++)
    {
        group_identity_t *g = &store->groups[i];
        fread(g->group_id, MAX_ID_LENGTH, 1, f);
        fread(g->sign_pk, CRYPTO_SIGN_PK_SIZE, 1, f);
        fread(g->sign_sk, CRYPTO_SIGN_SK_SIZE, 1, f);
        fread(g->kx_pk, CRYPTO_KX_PK_SIZE, 1, f);
        fread(g->kx_sk, CRYPTO_KX_SK_SIZE, 1, f);
        fread(g->binding_sig, CRYPTO_SIGN_SIZE, 1, f);
        fread(&g->created_at, sizeof(uint64_t), 1, f);

        uint8_t hash[32];
        sha256_hash(g->sign_pk, CRYPTO_SIGN_PK_SIZE, hash);
        memcpy(g->fingerprint, hash, IDENTITY_FINGERPRINT_SIZE);

        char hex[17];
        identity_bytes_to_hex(g->fingerprint, 8, hex, sizeof(hex));
        snprintf(g->ephemeral_id, MAX_ID_LENGTH, "eph_%s", hex);

        g->active = true;
    }

    fclose(f);
    store->loaded = true;

    return 0;
}

/*  Function: identity_store_find_group
    Description:
    Finds an active group identity in the store by group ID.

    Parameters:
    - store: Pointer to the identity_store_t structure.
    - group_id: The group ID to search for.

    Returns:
    - Pointer to the matching group_identity_t, or NULL if not found.

    Steps:
    1. Iterates through the store's group identities.
    2. Compares each active group's group_id with the given ID.
    3. Returns pointer if found, NULL otherwise.
*/
group_identity_t *identity_store_find_group(identity_store_t *store,
                                            const char *group_id)
{
    if (!store || !group_id)
        return NULL;

    for (int i = 0; i < store->group_count; i++)
    {
        if (strcmp(store->groups[i].group_id, group_id) == 0 &&
            store->groups[i].active)
        {
            return &store->groups[i];
        }
    }
    return NULL;
}

/*  Function: identity_store_remove_group
    Description:
    Removes a group identity from the store, securely zeroing its secret keys.

    Parameters:
    - store: Pointer to the identity_store_t structure.
    - group_id: The group ID to remove.

    Returns:
    - 0 on success, -1 if not found.

    Steps:
    1. Searches for the group by ID.
    2. Zeros the ephemeral secret keys (sign and kx).
    3. Shifts remaining groups left to fill the gap.
    4. Decrements the group count.
    5. Logs the removal event.
*/
int identity_store_remove_group(identity_store_t *store,
                                const char *group_id)
{
    if (!store || !group_id)
        return -1;

    for (int i = 0; i < store->group_count; i++)
    {
        if (strcmp(store->groups[i].group_id, group_id) == 0)
        {
            p2p_memzero(store->groups[i].sign_sk,
                        sizeof(store->groups[i].sign_sk));
            p2p_memzero(store->groups[i].kx_sk,
                        sizeof(store->groups[i].kx_sk));

            for (int j = i; j < store->group_count - 1; j++)
            {
                store->groups[j] = store->groups[j + 1];
            }
            store->group_count--;

            LOG_INFO("identity: Removed group identity for %s", group_id);
            return 0;
        }
    }
    return -1;
}