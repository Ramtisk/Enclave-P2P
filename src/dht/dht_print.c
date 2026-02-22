#include "dht_print.h"
#include "../common/logging.h"

/*  Function: dht_msg_type_string
    Description:
    Returns a human-readable string for a DHT message type.
*/
const char* dht_msg_type_string(dht_msg_type_t type) {
    switch (type) {
        case DHT_MSG_PING:             return "PING";
        case DHT_MSG_PONG:             return "PONG";
        case DHT_MSG_FIND_NODE:        return "FIND_NODE";
        case DHT_MSG_FIND_NODE_REPLY:  return "FIND_NODE_REPLY";
        case DHT_MSG_FIND_VALUE:       return "FIND_VALUE";
        case DHT_MSG_FIND_VALUE_REPLY: return "FIND_VALUE_REPLY";
        case DHT_MSG_STORE:            return "STORE";
        case DHT_MSG_STORE_ACK:        return "STORE_ACK";
        default:                       return "UNKNOWN";
    }
}

/*  Function: dht_print_status
    Description:
    Prints a formatted status box with routing table, storage, and network stats.

    Parameters:
    - ctx: DHT context.
*/
void dht_print_status(const dht_context_t* ctx) {
    if (!ctx) return;

    int total, good, used;
    routing_table_stats(&ctx->routing_table, &total, &good, &used);

    int entries, pinned;
    uint64_t bytes;
    dht_storage_stats(&ctx->storage, &entries, &pinned, &bytes);

    char hex[DHT_ID_BYTES * 2 + 1];
    dht_id_to_hex(&ctx->routing_table.self_id, hex, sizeof(hex));

    LOG_INFO("╔══════════════════════════════════════════════════╗");
    LOG_INFO("║                  DHT STATUS                      ║");
    LOG_INFO("╠══════════════════════════════════════════════════╣");
    LOG_INFO("║  Node ID:    %.40s ║", hex);
    LOG_INFO("║  UDP Port:   %-40d ║", ctx->listen_port);
    LOG_INFO("║  Running:    %-40s ║", ctx->running ? "YES" : "NO");
    LOG_INFO("╠══════════════════════════════════════════════════╣");
    LOG_INFO("║  ROUTING TABLE                                   ║");
    LOG_INFO("║    Total nodes:   %-33d ║", total);
    LOG_INFO("║    Good nodes:    %-33d ║", good);
    LOG_INFO("║    Buckets used:  %d/%-31d ║", used, DHT_BUCKET_COUNT);
    LOG_INFO("╠══════════════════════════════════════════════════╣");
    LOG_INFO("║  STORAGE                                         ║");
    LOG_INFO("║    Entries:       %d/%-31d ║", entries, DHT_MAX_ENTRIES);
    LOG_INFO("║    Pinned:        %-33d ║", pinned);
    LOG_INFO("║    Total bytes:   %-33lu ║", (unsigned long)bytes);
    LOG_INFO("╠══════════════════════════════════════════════════╣");
    LOG_INFO("║  NETWORK STATS                                   ║");
    LOG_INFO("║    Messages sent: %-33lu ║", (unsigned long)ctx->messages_sent);
    LOG_INFO("║    Messages recv: %-33lu ║", (unsigned long)ctx->messages_received);
    LOG_INFO("║    Lookups done:  %-33lu ║", (unsigned long)ctx->lookups_completed);
    LOG_INFO("║    Timeouts:      %-33lu ║", (unsigned long)ctx->timeouts);
    LOG_INFO("╚══════════════════════════════════════════════════╝");
}