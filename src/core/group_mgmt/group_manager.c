#include "group_manager.h"
#include "group_types.h"
#include "../../common/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Lifecycle */

/*  Function: group_manager_init
    Description:
    Initializes the group manager structure, zeroing all fields and initializing the mutex for thread safety.

    Parameters:
    - mgr: Pointer to the group_manager_t structure to initialize.

    Steps:
    1. Sets all fields of mgr to zero using memset.
    2. Initializes the mutex for concurrent access.
    3. Logs the initialization event.
*/
void group_manager_init(group_manager_t* mgr) {
    memset(mgr, 0, sizeof(group_manager_t));
    pthread_mutex_init(&mgr->mutex, NULL);
    LOG_INFO("Group manager initialized");
}

/*  Function: group_manager_cleanup
    Description:
    Cleans up the group manager by marking all groups as inactive, resetting the group count, and destroying the mutex.

    Parameters:
    - mgr: Pointer to the group_manager_t structure to clean up.

    Steps:
    1. Locks the mutex to ensure thread safety.
    2. Iterates through all groups, marking each as inactive.
    3. Resets the group count to zero.
    4. Unlocks and destroys the mutex.
    5. Logs the cleanup event.
*/
void group_manager_cleanup(group_manager_t* mgr) {
    pthread_mutex_lock(&mgr->mutex);
    
    for (int i = 0; i < MAX_GROUPS; i++) {
        mgr->groups[i].active = false;
    }
    mgr->group_count = 0;
    
    pthread_mutex_unlock(&mgr->mutex);
    pthread_mutex_destroy(&mgr->mutex);
    
    LOG_INFO("Group manager cleanup complete");
}

/* GROUP OPERATIONS */

/*  Function: group_create
    Description:
    Creates a new group with the specified name and founder information, assigns unique IDs, and adds the founder as the first member.

    Parameters:
    - mgr: Pointer to the group_manager_t structure.
    - name: Name of the group to create.
    - founder_id: ID of the user creating the group.
    - founder_ip: IP address of the founder.
    - founder_port: Port number of the founder.

    Returns:
    - Pointer to the newly created group_t structure, or NULL if the maximum number of groups is reached.

    Steps:
    1. Locks the mutex for thread safety.
    2. Searches for a free slot in the groups array.
    3. If no slot is available, logs a warning and returns NULL.
    4. Initializes the group structure and generates unique group and invite token IDs.
    5. Sets group metadata (name, founder, creation time, active flag).
    6. Increments the group count.
    7. Adds the founder as the first group member.
    8. Logs the group creation event.
    9. Unlocks the mutex and returns a pointer to the new group.
*/
group_t* group_create(group_manager_t* mgr, const char* name,
                      const char* founder_id, const char* founder_ip, uint16_t founder_port) {
    pthread_mutex_lock(&mgr->mutex);
    
    // Find free slot
    int slot = -1;
    for (int i = 0; i < MAX_GROUPS; i++) {
        if (!mgr->groups[i].active) {
            slot = i;
            break;
        }
    }
    
    if (slot < 0) {
        LOG_WARN("Cannot create group: max groups reached");
        pthread_mutex_unlock(&mgr->mutex);
        return NULL;
    }
    
    group_t* group = &mgr->groups[slot];
    memset(group, 0, sizeof(group_t));
    
    // Generate IDs
    generate_group_id(group->group_id, sizeof(group->group_id), name);
    generate_invite_token(group->invite_token, sizeof(group->invite_token));
    
    strncpy(group->group_name, name, MAX_GROUP_NAME - 1);
    strncpy(group->founder_id, founder_id, MAX_ID_LENGTH - 1);
    group->created_at = get_timestamp_ms();
    group->active = true;
    
    mgr->group_count++;
    
    // Add founder as first member
    group_add_member(group, founder_id, founder_ip, founder_port, true);
    
    LOG_INFO("Group created: %s (id: %s, token: %s, founder: %s)",
             name, group->group_id, group->invite_token, founder_id);
    
    pthread_mutex_unlock(&mgr->mutex);
    return group;
}

/*  Function: group_find_by_id
    Description:
    Searches for an active group by its unique group ID.

    Parameters:
    - mgr: Pointer to the group_manager_t structure.
    - group_id: The unique group ID to search for.

    Returns:
    - Pointer to the matching group_t structure, or NULL if not found.

    Steps:
    1. Iterates through all groups in the manager.
    2. Compares each active group's group_id with the provided group_id.
    3. Returns a pointer to the matching group if found, or NULL otherwise.
*/
group_t* group_find_by_id(group_manager_t* mgr, const char* group_id) {
    for (int i = 0; i < MAX_GROUPS; i++) {
        if (mgr->groups[i].active && 
            strcmp(mgr->groups[i].group_id, group_id) == 0) {
            return &mgr->groups[i];
        }
    }
    return NULL;
}

/*  Function: group_find_by_token
    Description:
    Searches for an active group by its invite token.

    Parameters:
    - mgr: Pointer to the group_manager_t structure.
    - invite_token: The invite token to search for.

    Returns:
    - Pointer to the matching group_t structure, or NULL if not found.

    Steps:
    1. Iterates through all groups in the manager.
    2. Compares each active group's invite_token with the provided token.
    3. Returns a pointer to the matching group if found, or NULL otherwise.
*/
group_t* group_find_by_token(group_manager_t* mgr, const char* invite_token) {
    for (int i = 0; i < MAX_GROUPS; i++) {
        if (mgr->groups[i].active && 
            strcmp(mgr->groups[i].invite_token, invite_token) == 0) {
            return &mgr->groups[i];
        }
    }
    return NULL;
}

/*  Function: group_destroy
    Description:
    Marks a group as inactive and decrements the group count.

    Parameters:
    - mgr: Pointer to the group_manager_t structure.
    - group_id: The unique group ID of the group to destroy.

    Returns:
    - 0 on success.
    - -1 if the group is not found.

    Steps:
    1. Locks the mutex for thread safety.
    2. Searches for the group by ID.
    3. If not found, unlocks the mutex and returns -1.
    4. Marks the group as inactive and decrements the group count.
    5. Logs the group destruction event.
    6. Unlocks the mutex and returns 0.
*/
int group_destroy(group_manager_t* mgr, const char* group_id) {
    pthread_mutex_lock(&mgr->mutex);
    
    group_t* group = group_find_by_id(mgr, group_id);
    if (!group) {
        pthread_mutex_unlock(&mgr->mutex);
        return -1;
    }
    
    LOG_INFO("Destroying group: %s (%s)", group->group_name, group->group_id);
    
    group->active = false;
    mgr->group_count--;
    
    pthread_mutex_unlock(&mgr->mutex);
    return 0;
}

/* TOKEN OPERATIONS */

/*  Function: group_regenerate_token
    Description:
    Generates a new invite token for the specified group.

    Parameters:
    - group: Pointer to the group_t structure.

    Steps:
    1. Calls the token generation function to create a new invite token.
    2. Logs the token regeneration event.
*/
void group_regenerate_token(group_t* group) {
    generate_invite_token(group->invite_token, sizeof(group->invite_token));
    LOG_INFO("Regenerated invite token for group %s: %s",
             group->group_id, group->invite_token);
}