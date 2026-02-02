#ifndef P2P_GROUP_MGMT_H
#define P2P_GROUP_MGMT_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "../common/config.h"
#include "../common/protocol.h"

// ============================================
// GROUP MEMBER
// ============================================
typedef struct {
    char client_id[MAX_ID_LENGTH];
    char ip[46];
    uint16_t port;
    bool is_founder;
    uint64_t joined_at;
} group_member_t;

// ============================================
// PENDING JOIN REQUEST
// ============================================
typedef struct {
    char request_id[MAX_ID_LENGTH];
    char requester_id[MAX_ID_LENGTH];
    char requester_ip[46];
    uint16_t requester_port;
    uint64_t requested_at;
    
    // Vote tracking
    int votes_received;
    int votes_approved;
    int votes_needed;
    bool votes[MAX_GROUP_MEMBERS];  // Track who voted
    bool completed;
} pending_join_t;

// ============================================
// GROUP STRUCTURE
// ============================================
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

// ============================================
// GROUP MANAGER
// ============================================
typedef struct {
    group_t groups[MAX_GROUPS];
    int group_count;
    pthread_mutex_t mutex;
} group_manager_t;

// ============================================
// FUNCTIONS
// ============================================

// Lifecycle
void group_manager_init(group_manager_t* mgr);
void group_manager_cleanup(group_manager_t* mgr);

// Group operations
group_t* group_create(group_manager_t* mgr, const char* name, 
                      const char* founder_id, const char* founder_ip, uint16_t founder_port);
group_t* group_find_by_id(group_manager_t* mgr, const char* group_id);
group_t* group_find_by_token(group_manager_t* mgr, const char* invite_token);
int group_destroy(group_manager_t* mgr, const char* group_id);

// Member operations
int group_add_member(group_t* group, const char* client_id, 
                     const char* ip, uint16_t port, bool is_founder);
int group_remove_member(group_t* group, const char* client_id);
group_member_t* group_find_member(group_t* group, const char* client_id);
bool group_is_member(group_t* group, const char* client_id);

// Join request operations
pending_join_t* group_create_join_request(group_t* group, const char* requester_id,
                                          const char* ip, uint16_t port);
pending_join_t* group_find_pending_join(group_t* group, const char* request_id);
int group_register_vote(group_t* group, const char* request_id, 
                        const char* voter_id, bool approved);
int group_check_vote_result(group_t* group, const char* request_id);
void group_cleanup_pending(group_t* group, const char* request_id);

// Token operations
void group_regenerate_token(group_t* group);

// Utility
void generate_group_id(char* id, size_t len, const char* name);
void generate_invite_token(char* token, size_t len);
void generate_request_id(char* id, size_t len);

#endif // P2P_GROUP_MGMT_H