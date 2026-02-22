#ifndef P2P_BANDWIDTH_H
#define P2P_BANDWIDTH_H

#include <stdint.h>
#include "scheduler_types.h"

void bandwidth_init(bandwidth_tracker_t* bw);
void bandwidth_record(bandwidth_tracker_t* bw, uint32_t bytes, uint64_t elapsed_ms);
double bandwidth_get_rate(const bandwidth_tracker_t* bw);

#endif