#ifndef GROUP_TYPES_H
#define GROUP_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "../../common/config.h"
#include "../../common/protocol.h"

/*  ============================================
    GROUP MEMBER STRUCTURE

    Note: Represents a single member of a group.
    - client_id: Unique identifier for the client.
    - ip: IP address of the member (supports IPv4/IPv6).
    - port: Port number used by the member.
    - is_founder: True if this member is the group founder.
    - joined_at: Timestamp (epoch ms) when the member joined.
    ============================================ */
typedef struct {
    char client_id[MAX_ID_LENGTH];
    char ip[46];
    uint16_t port;
    bool is_founder;
    uint64_t joined_at;
} group_member_t;

/*  ============================================
    PENDING JOIN STRUCTURE

    Note: Represents a pending join request for a group.
    - request_id: Unique identifier for the join request.
    - requester_id: ID of the client requesting to join.
    - requester_ip: IP address of the requester.
    - requester_port: Port number of the requester.
    - requested_at: Timestamp (epoch ms) when the request was made.
    - votes_received: Number of votes received so far.
    - votes_approved: Number of approval votes.
    - votes_needed: Total votes required (usually member count).
    - votes: Array indicating which members have voted.
    - completed: True if voting is finished for this request.
    ============================================ */
typedef struct {
    char request_id[MAX_ID_LENGTH];
    char requester_id[MAX_ID_LENGTH];
    char requester_ip[46];
    uint16_t requester_port;
    uint64_t requested_at;
    int votes_received;
    int votes_approved;
    int votes_needed;
    bool votes[MAX_GROUP_MEMBERS];
    bool completed;
} pending_join_t;

/*  ============================================
    GROUP STRUCTURE

    Note: Represents a group (enclave) in the system.
    - group_id: Unique identifier for the group.
    - group_name: Human-readable group name.
    - invite_token: Token used to invite new members.
    - created_at: Timestamp (epoch ms) when the group was created.
    - founder_id: ID of the group founder.
    - members: Array of group members.
    - member_count: Current number of members.
    - pending_joins: Array of pending join requests.
    - pending_count: Number of pending join requests.
    - active: True if the group is active.
    ============================================ */
typedef struct {
    char group_id[MAX_ID_LENGTH];
    char group_name[MAX_GROUP_NAME];
    char invite_token[INVITE_TOKEN_LENGTH];
    uint64_t created_at;
    char founder_id[MAX_ID_LENGTH];
    group_member_t members[MAX_GROUP_MEMBERS];
    int member_count;
    pending_join_t pending_joins[MAX_PENDING_JOINS];
    int pending_count;
    bool active;
} group_t;

/*  ============================================
    GROUP MANAGER STRUCTURE

    Note: Manages all groups in the system.
    - groups: Array of all group structures.
    - group_count: Number of active groups.
    - mutex: Mutex for thread-safe access to the group manager.
    ============================================ */
typedef struct {
    group_t groups[MAX_GROUPS];
    int group_count;
    pthread_mutex_t mutex;
} group_manager_t;

#endif