#ifndef GROUP_JOIN_H
#define GROUP_JOIN_H

#include "group_types.h"

/* Join */
pending_join_t* group_create_join_request(group_t* group, const char* requester_id, const char* ip, uint16_t port);
pending_join_t* group_find_pending_join(group_t* group, const char* request_id);
int group_register_vote(group_t* group, const char* request_id, const char* voter_id, bool approved);
int group_check_vote_result(group_t* group, const char* request_id);
void group_cleanup_pending(group_t* group, const char* request_id);

#endif