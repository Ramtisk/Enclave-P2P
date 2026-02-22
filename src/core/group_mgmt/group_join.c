#include "group_join.h"
#include "group_utils.h"
#include "group_types.h"
#include "common/logging.h"

#include <stdio.h>
#include <stdlib.h>

/* Join */

/*  Function: group_create_join_request
    Description:
    Creates a new pending join request for a group. Initializes the pending_join_t structure,
    assigns a unique request ID, sets requester information, and marks the request as pending.

    Parameters:
    - group: Pointer to the group_t structure where the join is requested.
    - requester_id: ID of the client requesting to join.
    - ip: IP address of the requester.
    - port: Port number of the requester.

    Returns:
    - Pointer to the newly created pending_join_t structure, or NULL if the maximum number of pending joins is reached.

    Steps:
    1. Checks if the group already has the maximum number of pending join requests.
    2. If not, gets the next available pending_join_t slot in the group's array.
    3. Clears the structure with memset to ensure a clean state.
    4. Generates a unique request ID for this join request.
    5. Copies the requester ID and IP address into the structure.
    6. Sets the requester port and the request timestamp.
    7. Sets the number of votes needed to the current group member count (unanimous approval).
    8. Marks the request as not completed.
    9. Increments the group's pending join count.
    10. Logs the creation of the join request.
    11. Returns a pointer to the new pending_join_t structure.
*/
pending_join_t* group_create_join_request(group_t* group, const char* requester_id,
                                          const char* ip, uint16_t port) {
    if (group->pending_count >= MAX_PENDING_JOINS) {
        LOG_WARN("Cannot create join request: too many pending");
        return NULL;
    }
    
    pending_join_t* pending = &group->pending_joins[group->pending_count];
    memset(pending, 0, sizeof(pending_join_t));
    
    generate_request_id(pending->request_id, sizeof(pending->request_id));
    strncpy(pending->requester_id, requester_id, MAX_ID_LENGTH - 1);
    strncpy(pending->requester_ip, ip, sizeof(pending->requester_ip) - 1);
    pending->requester_port = port;
    pending->requested_at = get_timestamp_ms();
    pending->votes_needed = group->member_count;  // All must approve
    pending->completed = false;
    
    group->pending_count++;
    
    LOG_INFO("Created join request %s for %s in group %s (need %d votes)",
             pending->request_id, requester_id, group->group_id, pending->votes_needed);
    
    return pending;
}

/*  Function: group_find_pending_join
    Description:
    Searches for a pending join request in the group's pending_joins array by request ID.

    Parameters:
    - group: Pointer to the group_t structure.
    - request_id: The unique request ID to search for.

    Returns:
    - Pointer to the matching pending_join_t structure, or NULL if not found.

    Steps:
    1. Iterates through the group's pending_joins array up to pending_count.
    2. Compares each pending join's request_id with the given request_id.
    3. Returns a pointer to the matching pending_join_t if found.
    4. Returns NULL if no match is found.
*/
pending_join_t* group_find_pending_join(group_t* group, const char* request_id) {
    for (int i = 0; i < group->pending_count; i++) {
        if (strcmp(group->pending_joins[i].request_id, request_id) == 0) {
            return &group->pending_joins[i];
        }
    }
    return NULL;
}

/*  Function: group_register_vote
    Description:
    Registers a vote (approve or reject) from a group member for a specific join request.
    Ensures each member can only vote once per request.

    Parameters:
    - group: Pointer to the group_t structure.
    - request_id: The join request ID being voted on.
    - voter_id: The ID of the member casting the vote.
    - approved: Boolean indicating if the vote is an approval (true) or rejection (false).

    Returns:
    - 0 on success.
    - -1 if the request is not found or already completed.
    - -2 if the voter is not a group member.
    - -3 if the member has already voted on this request.

    Steps:
    1. Finds the pending join request by request_id.
    2. Returns -1 if not found or already completed.
    3. Searches for the voter in the group's members array.
    4. Returns -2 if the voter is not a member.
    5. Checks if the member has already voted; returns -3 if so.
    6. Marks the member as having voted and increments votes_received.
    7. Increments votes_approved if the vote is approved.
    8. Logs the vote registration.
    9. Returns 0 on success.
*/
int group_register_vote(group_t* group, const char* request_id,
                        const char* voter_id, bool approved) {
    pending_join_t* pending = group_find_pending_join(group, request_id);
    if (!pending || pending->completed) {
        return -1;
    }
    
    // Find voter index
    int voter_index = -1;
    for (int i = 0; i < group->member_count; i++) {
        if (strcmp(group->members[i].client_id, voter_id) == 0) {
            voter_index = i;
            break;
        }
    }
    
    if (voter_index < 0) {
        LOG_WARN("Voter %s is not a member of group", voter_id);
        return -2;
    }
    
    if (pending->votes[voter_index]) {
        LOG_WARN("Member %s already voted on request %s", voter_id, request_id);
        return -3;
    }
    
    pending->votes[voter_index] = true;
    pending->votes_received++;
    if (approved) {
        pending->votes_approved++;
    }
    
    LOG_INFO("Vote registered: %s voted %s on request %s (%d/%d votes, %d approved)",
             voter_id, approved ? "YES" : "NO", request_id,
             pending->votes_received, pending->votes_needed, pending->votes_approved);
    
    return 0;
}

/*  Function: group_check_vote_result
    Description:
    Checks if all votes for a join request have been received and determines the result.
    Marks the request as completed.

    Parameters:
    - group: Pointer to the group_t structure.
    - request_id: The join request ID to check.

    Returns:
    - 1 if the request is unanimously approved.
    - -1 if the request is rejected.
    - 0 if voting is still in progress.

    Steps:
    1. Finds the pending join request by request_id.
    2. Returns -1 if not found.
    3. Checks if all votes have been received; returns 0 if not.
    4. If all votes are received, checks if all are approved.
    5. Marks the request as completed.
    6. Returns 1 if unanimously approved, -1 if rejected.
*/
int group_check_vote_result(group_t* group, const char* request_id) {
    pending_join_t* pending = group_find_pending_join(group, request_id);
    if (!pending) return -1;
    
    // Check if voting is complete
    if (pending->votes_received < pending->votes_needed) {
        return 0;  // Still waiting for votes
    }
    
    // All votes received - check result
    // Requires unanimous approval
    if (pending->votes_approved == pending->votes_needed) {
        pending->completed = true;
        return 1;  // Approved
    } else {
        pending->completed = true;
        return -1;  // Rejected
    }
}

/*  Function: group_cleanup_pending
    Description:
    Removes a pending join request from the group's pending_joins array after it is completed or cancelled.

    Parameters:
    - group: Pointer to the group_t structure.
    - request_id: The join request ID to remove.

    Returns:
    - None (void function).

    Steps:
    1. Searches for the pending join request by request_id.
    2. If found, shifts all subsequent pending_joins left to fill the gap.
    3. Decrements the group's pending_count.
    4. Logs the cleanup action.
*/
void group_cleanup_pending(group_t* group, const char* request_id) {
    for (int i = 0; i < group->pending_count; i++) {
        if (strcmp(group->pending_joins[i].request_id, request_id) == 0) {
            // Shift remaining
            for (int j = i; j < group->pending_count - 1; j++) {
                group->pending_joins[j] = group->pending_joins[j + 1];
            }
            group->pending_count--;
            LOG_DEBUG("Cleaned up pending request %s", request_id);
            return;
        }
    }
}