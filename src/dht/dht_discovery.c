#define _POSIX_C_SOURCE 200809L
#include "dht_discovery.h"
#include "dht_lookup.h"
#include "../common/logging.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/*  Function: dht_announce_peer
    Description:
    Announces this node's presence for a group by storing "ip:port" under
    SHA-256(group_id) in the DHT.

    Parameters:
    - ctx: DHT context.
    - group_id: Group name string.
    - ip: Announce IP (NULL = use listen_ip).
    - port: Announce port (0 = use listen_port).

    Returns:
    - 0 on success, -1 on failure.

    Steps:
    1. Derives a 160-bit key from SHA-256(group_id).
    2. Formats the value as "ip:port".
    3. Calls dht_store to replicate to closest nodes.
*/
int dht_announce_peer(dht_context_t* ctx, const char* group_id,
                      const char* ip, uint16_t port) {
    if (!ctx || !group_id) return -1;

    dht_node_id_t key;
    dht_id_from_data(&key, (const uint8_t*)group_id, strlen(group_id));

    char value[64];
    int vlen = snprintf(value, sizeof(value), "%s:%d",
                        ip ? ip : ctx->listen_ip,
                        port ? port : ctx->listen_port);

    int result = dht_store(ctx, &key, (const uint8_t*)value, (size_t)vlen + 1,
                            DHT_DEFAULT_TTL_S);

    if (result == 0) {
        LOG_INFO("dht: Announced peer for group '%s' as %s", group_id, value);
    }
    return result;
}

/*  Function: dht_find_peers
    Description:
    Finds peers for a named group. Tries FIND_VALUE first; falls back to
    returning closest nodes.

    Parameters:
    - ctx: DHT context.
    - group_id: Group name string.
    - peers_out: Output array for discovered peers.
    - max_peers: Maximum entries.

    Returns:
    - Number of peers found.

    Steps:
    1. Derives the key from group_id.
    2. Calls dht_find_value. If found, parses "ip:port" and returns 1 peer.
    3. If not found, calls routing_table_find_closest as a fallback.
*/
int dht_find_peers(dht_context_t* ctx, const char* group_id,
                   dht_node_t* peers_out, int max_peers) {
    if (!ctx || !group_id || !peers_out || max_peers <= 0) return 0;

    dht_node_id_t key;
    dht_id_from_data(&key, (const uint8_t*)group_id, strlen(group_id));

    uint8_t value[DHT_MAX_VALUE_SIZE];
    size_t vlen = sizeof(value);

    if (dht_find_value(ctx, &key, value, &vlen) == 0 && vlen > 0) {
        char* str = (char*)value;
        char* colon = strchr(str, ':');
        if (colon && colon > str) {
            *colon = '\0';

            dht_node_t peer;
            memset(&peer, 0, sizeof(peer));
            strncpy(peer.ip, str, sizeof(peer.ip) - 1);
            peer.port = (uint16_t)atoi(colon + 1);
            dht_id_from_data(&peer.id, (const uint8_t*)str, strlen(str));
            peer.last_seen = get_timestamp_ms();
            peer.is_good = true;

            peers_out[0] = peer;

            LOG_INFO("dht: Found peer for group '%s': %s:%d",
                     group_id, peer.ip, peer.port);
            return 1;
        }
    }

    int found = routing_table_find_closest(&ctx->routing_table, &key,
                                            peers_out, max_peers);
    LOG_DEBUG("dht: No announced peers for group '%s', returning %d closest nodes",
              group_id, found);
    return found;
}