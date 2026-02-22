#define _POSIX_C_SOURCE 200809L
#include "dht_maintenance.h"
#include "dht_lookup.h"
#include "dht_pending.h"
#include "../common/logging.h"

#include <unistd.h>

/*  Function: dht_maintenance_thread
    Description:
    Background thread performing periodic DHT housekeeping tasks.

    Parameters:
    - arg: Pointer to dht_context_t (cast from void*).

    Returns:
    - NULL on exit.

    Steps (every 60 seconds):
    1. Expires old pending request slots.
    2. Expires old storage entries (TTL-based).
    3. Pings up to 10 stale nodes and removes those with 3+ failed pings.
    4. Every 60 ticks (~1 hour): republishes values needing re-announcement.
    5. Every 60 ticks: refreshes routing table buckets that haven't changed recently.
    6. Every 5 ticks: logs a periodic stats summary.
*/
void* dht_maintenance_thread(void* arg) {
    dht_context_t* ctx = (dht_context_t*)arg;

    LOG_INFO("dht: Maintenance thread started (interval=60s)");

    int tick = 0;

    while (ctx->running) {
        for (int i = 0; i < 60 && ctx->running; i++) {
            sleep(1);
        }
        if (!ctx->running) break;

        tick++;

        // ── Expire old pending requests ──
        dht_pending_expire(ctx);

        // ── Expire old storage entries ──
        int expired = dht_storage_expire(&ctx->storage);

        // ── Ping stale nodes ──
        dht_node_t stale[10];
        int stale_count = routing_table_get_stale(&ctx->routing_table, stale, 10);
        for (int i = 0; i < stale_count && ctx->running; i++) {
            dht_ping(ctx, stale[i].ip, stale[i].port);
        }

        // ── Remove dead nodes (failed 3+ pings) ──
        for (int i = 0; i < stale_count; i++) {
            if (stale[i].failed_pings >= 3) {
                routing_table_remove(&ctx->routing_table, &stale[i].id);
                LOG_DEBUG("dht: Removed dead node %s:%d (3+ failed pings)",
                          stale[i].ip, stale[i].port);
            }
        }

        // ── Republish values (every ~60 minutes) ──
        if (tick % 60 == 0) {
            dht_node_id_t keys[32];
            int republish_count = dht_storage_get_republish(&ctx->storage, keys, 32);

            for (int i = 0; i < republish_count && ctx->running; i++) {
                uint8_t val[DHT_MAX_VALUE_SIZE];
                size_t vlen = sizeof(val);
                if (dht_storage_get(&ctx->storage, &keys[i], val, &vlen) == 0) {
                    dht_store(ctx, &keys[i], val, vlen, DHT_DEFAULT_TTL_S);
                    dht_storage_mark_republished(&ctx->storage, &keys[i]);
                }
            }

            if (republish_count > 0) {
                LOG_INFO("dht: Republished %d values", republish_count);
            }
        }

        // ── Refresh empty buckets (every ~60 minutes) ──
        if (tick % 60 == 0) {
            int bucket_indices[20];
            int refresh_count = routing_table_get_refresh_buckets(
                &ctx->routing_table, bucket_indices, 20);

            for (int i = 0; i < refresh_count && ctx->running; i++) {
                dht_node_id_t random_target;
                dht_id_random(&random_target);

                dht_node_t dummy[DHT_K_BUCKET_SIZE];
                dht_find_node(ctx, &random_target, dummy, DHT_K_BUCKET_SIZE);
            }

            if (refresh_count > 0) {
                LOG_DEBUG("dht: Refreshed %d buckets", refresh_count);
            }
        }

        // ── Periodic stats log ──
        if (tick % 5 == 0) {
            int total, good, used;
            routing_table_stats(&ctx->routing_table, &total, &good, &used);
            LOG_DEBUG("dht: Maintenance — nodes=%d/%d good, storage expired=%d, "
                      "stale pinged=%d",
                      good, total, expired, stale_count);
        }
    }

    LOG_INFO("dht: Maintenance thread stopped");
    return NULL;
}