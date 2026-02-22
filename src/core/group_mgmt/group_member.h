#ifndef GROUP_MEMBER_H
#define GROUP_MEMBER_H

#include "group_types.h"

/* Member operations */
int group_add_member(group_t* group, const char* client_id, const char* ip, uint16_t port, bool is_founder);
int group_remove_member(group_t* group, const char* client_id);
group_member_t* group_find_member(group_t* group, const char* client_id);
bool group_is_member(group_t* group, const char* client_id);

#endif