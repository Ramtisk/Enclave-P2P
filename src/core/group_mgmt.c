#include "group_mgmt.h"
#include "../common/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// ============================================
// UTILITY FUNCTIONS
// ============================================

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void generate_group_id(char* id, size_t len, const char* name) {
    // Create hash-like ID from name + timestamp
    uint64_t ts = get_timestamp_ms();
    uint32_t hash = 5381;
    
    for (const char* c = name; *c; c++) {
        hash = ((hash << 5) + hash) + (uint8_t)*c;
    }
    hash ^= (uint32_t)(ts & 0xFFFFFFFF);
    
    snprintf(id, len, "grp_%08x", hash);
}

void generate_invite_token(char* token, size_t len) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    size_t charset_len = sizeof(charset) - 1;
    
    srand((unsigned int)(get_timestamp_ms() ^ getpid()));
    
    size_t token_len = len - 1;
    if (token_len > INVITE_TOKEN_LENGTH - 1) {
        token_len = INVITE_TOKEN_LENGTH - 1;
    }
    
    for (size_t i = 0; i < token_len; i++) {
        token[i] = charset[rand() % charset_len];
    }
    token[token_len] = '\0';
}

void generate_request_id(char* id, size_t len) {
    snprintf(id, len, "req_%lu_%d", get_timestamp_ms(), rand() % 10000);
}

// ============================================
// LIFECYCLE
// ============================================

void group_manager_init(group_manager_t* mgr) {
    memset(mgr, 0, sizeof(group_manager_t));
    pthread_mutex_init(&mgr->mutex, NULL);
    LOG_INFO("Group manager initialized");
}

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

// ============================================
// GROUP OPERATIONS
// ============================================

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

group_t* group_find_by_id(group_manager_t* mgr, const char* group_id) {
    for (int i = 0; i < MAX_GROUPS; i++) {
        if (mgr->groups[i].active && 
            strcmp(mgr->groups[i].group_id, group_id) == 0) {
            return &mgr->groups[i];
        }
    }
    return NULL;
}

group_t* group_find_by_token(group_manager_t* mgr, const char* invite_token) {
    for (int i = 0; i < MAX_GROUPS; i++) {
        if (mgr->groups[i].active && 
            strcmp(mgr->groups[i].invite_token, invite_token) == 0) {
            return &mgr->groups[i];
        }
    }
    return NULL;
}

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

// ============================================
// MEMBER OPERATIONS
// ============================================

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

group_member_t* group_find_member(group_t* group, const char* client_id) {
    for (int i = 0; i < group->member_count; i++) {
        if (strcmp(group->members[i].client_id, client_id) == 0) {
            return &group->members[i];
        }
    }
    return NULL;
}

bool group_is_member(group_t* group, const char* client_id) {
    return group_find_member(group, client_id) != NULL;
}

// ============================================
// JOIN REQUEST OPERATIONS
// ============================================

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

pending_join_t* group_find_pending_join(group_t* group, const char* request_id) {
    for (int i = 0; i < group->pending_count; i++) {
        if (strcmp(group->pending_joins[i].request_id, request_id) == 0) {
            return &group->pending_joins[i];
        }
    }
    return NULL;
}

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

// ============================================
// TOKEN OPERATIONS
// ============================================

void group_regenerate_token(group_t* group) {
    generate_invite_token(group->invite_token, sizeof(group->invite_token));
    LOG_INFO("Regenerated invite token for group %s: %s",
             group->group_id, group->invite_token);
}