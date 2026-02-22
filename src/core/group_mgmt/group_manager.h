#ifndef GROUP_MANAGER_H
#define GROUP_MANAGER_H

#include "group_types.h"
#include "group_member.h"
#include "group_join.h"
#include "group_utils.h"

/* Lifecycle */
void group_manager_init(group_manager_t* mgr);
void group_manager_cleanup(group_manager_t* mgr);

/* Group operations */
group_t* group_create(group_manager_t* mgr, const char* name, const char* founder_id, const char* founder_ip, uint16_t founder_port);
group_t* group_find_by_id(group_manager_t* mgr, const char* group_id);
group_t* group_find_by_token(group_manager_t* mgr, const char* invite_token);
int group_destroy(group_manager_t* mgr, const char* group_id);

/* Token */
void group_regenerate_token(group_t* group);

#endif