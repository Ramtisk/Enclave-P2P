#include "group_member.h"
#include "group_utils.h"
#include "common/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/*  Function: group_add_member
    Description:
    Adds a new member to the group. Initializes the group_member_t structure, sets member details,
    and updates the group's member count.

    Parameters:
    - group: Pointer to the group_t structure.
    - client_id: ID of the client to add.
    - ip: IP address of the client.
    - port: Port number of the client.
    - is_founder: Boolean indicating if the member is the group founder.

    Returns:
    - 0 on success.
    - -1 if the group is full.
    - -2 if the client is already a member.

    Steps:
    1. Checks if the group is full; returns -1 if so.
    2. Checks if the client is already a member; returns -2 if so.
    3. Initializes the next available group_member_t structure.
    4. Sets client ID, IP, port, founder flag, and join timestamp.
    5. Increments the group's member count.
    6. Logs the addition.
    7. Returns 0 on success.
*/
int group_add_member(group_t* group, const char* client_id,
                     const char* ip, uint16_t port, bool is_founder) {
    if (group->member_count >= MAX_GROUP_MEMBERS) {
        LOG_WARN("Cannot add member: group full");
        return -1;
    }
    
    // Check if already a member
    if (group_is_member(group, client_id)) {
        LOG_WARN("Client %s is already a member of group %s", 
                 client_id, group->group_id);
        return -2;
    }
    
    group_member_t* member = &group->members[group->member_count];
    memset(member, 0, sizeof(group_member_t));
    
    strncpy(member->client_id, client_id, MAX_ID_LENGTH - 1);
    strncpy(member->ip, ip, sizeof(member->ip) - 1);
    member->port = port;
    member->is_founder = is_founder;
    member->joined_at = get_timestamp_ms();
    
    group->member_count++;
    
    LOG_INFO("Added member %s to group %s [%d members]",
             client_id, group->group_id, group->member_count);
    
    return 0;
}

/*  Function: group_remove_member
    Description:
    Removes a member from the group by client ID. Shifts remaining members to fill the gap and updates the member count.

    Parameters:
    - group: Pointer to the group_t structure.
    - client_id: ID of the client to remove.

    Returns:
    - 0 on success.
    - -1 if the client is not found.

    Steps:
    1. Searches for the member by client ID.
    2. If found, logs the removal.
    3. Shifts remaining members left to fill the gap.
    4. Decrements the group's member count.
    5. Logs the updated member count.
    6. Returns 0 on success.
    7. Returns -1 if not found.
*/
int group_remove_member(group_t* group, const char* client_id) {
    for (int i = 0; i < group->member_count; i++) {
        if (strcmp(group->members[i].client_id, client_id) == 0) {
            LOG_INFO("Removing member %s from group %s",
                     client_id, group->group_id);
            
            // Shift remaining members
            for (int j = i; j < group->member_count - 1; j++) {
                group->members[j] = group->members[j + 1];
            }
            group->member_count--;
            
            LOG_INFO("Group %s now has %d members", 
                     group->group_id, group->member_count);
            
            return 0;
        }
    }
    return -1;
}

/*  Function: group_find_member
    Description:
    Finds and returns a pointer to a group member by client ID.

    Parameters:
    - group: Pointer to the group_t structure.
    - client_id: ID of the client to find.

    Returns:
    - Pointer to the group_member_t structure if found.
    - NULL if not found.

    Steps:
    1. Iterates through the group's members.
    2. Compares each member's client ID with the given ID.
    3. Returns pointer if found, NULL otherwise.
*/
group_member_t* group_find_member(group_t* group, const char* client_id) {
    for (int i = 0; i < group->member_count; i++) {
        if (strcmp(group->members[i].client_id, client_id) == 0) {
            return &group->members[i];
        }
    }
    return NULL;
}

/*  Function: group_is_member
    Description:
    Checks if a client is a member of the group.

    Parameters:
    - group: Pointer to the group_t structure.
    - client_id: ID of the client to check.

    Returns:
    - true if the client is a member.
    - false otherwise.

    Steps:
    1. Calls group_find_member to check membership.
    2. Returns true if found, false otherwise.
*/
bool group_is_member(group_t* group, const char* client_id) {
    return group_find_member(group, client_id) != NULL;
}