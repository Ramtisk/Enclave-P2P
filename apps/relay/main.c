#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include "../../src/common/config.h"
#include "../../src/common/logging.h"
#include "../../src/network/relay.h"

static relay_server_t g_server;

void signal_handler(int sig) {
    (void)sig;
    printf("\n");
    LOG_INFO("Signal received, shutting down...");
    relay_stop(&g_server);
}

void print_usage(const char* prog) {
    printf("P2P Relay Server v%d.%d.%d\n\n", 
           P2P_VERSION_MAJOR, P2P_VERSION_MINOR, P2P_VERSION_PATCH);
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -p PORT   Server port (default: %d)\n", RELAY_PORT);
    printf("  -l FILE   Log file path\n");
    printf("  -v        Verbose mode (debug logging)\n");
    printf("  -h        Show this help\n");
}

int main(int argc, char* argv[]) {
    uint16_t port = RELAY_PORT;
    const char* log_file = NULL;
    log_level_t log_level = LOG_INFO;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            log_file = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            log_level = LOG_DEBUG;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    // Initialize logging
    log_init(log_level, log_file);
    
    LOG_INFO("========================================");
    LOG_INFO("  P2P Relay Server v%d.%d.%d", 
             P2P_VERSION_MAJOR, P2P_VERSION_MINOR, P2P_VERSION_PATCH);
    LOG_INFO("========================================");
    
    // Register signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize server
    if (relay_init(&g_server, port) != 0) {
        LOG_FATAL("Failed to initialize relay");
        return 1;
    }
    
    LOG_INFO("Press Ctrl+C to stop");
    
    // Start main loop
    relay_start(&g_server);
    
    // Cleanup
    relay_cleanup(&g_server);
    log_shutdown();
    
    printf("Relay server stopped.\n");
    return 0;
}