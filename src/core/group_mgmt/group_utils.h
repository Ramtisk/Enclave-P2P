#ifndef GROUP_UTILS_H
#define GROUP_UTILS_H

#include <stddef.h>
#include <stdint.h>

/* utils */

void generate_group_id(char* id, size_t len, const char* name);
void generate_invite_token(char* token, size_t len);
void generate_request_id(char* id, size_t len);
uint64_t get_timestamp_ms(void);

#endif