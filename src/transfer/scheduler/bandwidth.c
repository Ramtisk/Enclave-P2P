#include "bandwidth.h"
#include <string.h>
#include <time.h>

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void bandwidth_init(bandwidth_tracker_t* bw) {
    memset(bw, 0, sizeof(bandwidth_tracker_t));
    bw->started_at = get_timestamp_ms();
}

void bandwidth_record(bandwidth_tracker_t* bw, uint32_t bytes, uint64_t elapsed_ms) {
    if (elapsed_ms == 0) elapsed_ms = 1;
    double rate = (double)bytes / ((double)elapsed_ms / 1000.0);
    bw->samples[bw->head] = rate;
    bw->head = (bw->head + 1) % BANDWIDTH_WINDOW_SIZE;
    if (bw->sample_count < BANDWIDTH_WINDOW_SIZE) bw->sample_count++;
    bw->current_bps = rate;
    bw->total_bytes += bytes;
    if (rate > bw->peak_bps) bw->peak_bps = rate;
    double sum = 0;
    for (int i = 0; i < bw->sample_count; i++) sum += bw->samples[i];
    bw->avg_bps = sum / bw->sample_count;
}

double bandwidth_get_rate(const bandwidth_tracker_t* bw) {
    return bw->avg_bps;
}