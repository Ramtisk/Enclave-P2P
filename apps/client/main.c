#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

#include "../../src/common/config.h"
#include "../../src/common/logging.h"
#include "../../src/network/client.h"

static p2p_client_t g_client;
static volatile int g_running = 1;

void signal_handler(int sig) {
    (void)sig;
    printf("\n");
    LOG_INFO("Signal received, shutting down...");
    g_running = 0;
}

void on_message_received(message_t* msg, void* user_data) {
    (void)user_data;
    
    switch (msg->header.type) {
        case MSG_ACK:
            LOG_INFO("Received ACK from relay - connection confirmed!");
            break;
        case MSG_PONG:
            // Handled internally in client.c
            break;
        default:
            LOG_DEBUG("Received message: type=%s from=%s", 
                     message_type_string(msg->header.type), 
                     msg->header.sender_id);
            break;
    }
}

void print_usage(const char* prog) {
    printf("P2P Client v%d.%d.%d\n\n", 
           P2P_VERSION_MAJOR, P2P_VERSION_MINOR, P2P_VERSION_PATCH);
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -r HOST   Relay host (default: %s)\n", RELAY_HOST);
    printf("  -p PORT   Relay port (default: %d)\n", RELAY_PORT);
    printf("  -v        Verbose mode (debug logging)\n");
    printf("  -h        Show this help\n");
}

void print_commands(void) {
    printf("\nCommands:\n");
    printf("  s - Show status\n");
    printf("  p - Send ping\n");
    printf("  q - Quit\n");
    printf("\n> ");
    fflush(stdout);
}

void print_status(p2p_client_t* client) {
    printf("\n");
    printf("======== Client Status ========\n");
    printf("  ID:           %s\n", client->id);
    printf("  Connected:    %s\n", client->connected ? "Yes" : "No");
    printf("  Relay:        %s:%d\n", client->relay_host, client->relay_port);
    printf("  RTT:          %lu ms\n", client->rtt_ms);
    printf("  Pings sent:   %u\n", client->ping_counter);
    printf("  Msgs sent:    %lu\n", client->messages_sent);
    printf("  Msgs recv:    %lu\n", client->messages_received);
    printf("===============================\n");
    printf("\n> ");
    fflush(stdout);
}

int main(int argc, char* argv[]) {
    const char* relay_host = RELAY_HOST;
    uint16_t relay_port = RELAY_PORT;
    log_level_t log_level = LOG_INFO;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            relay_host = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            relay_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "-v") == 0) {
            log_level = LOG_DEBUG;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    // Initialize logging
    log_init(log_level, NULL);
    
    LOG_INFO("========================================");
    LOG_INFO("  P2P Client v%d.%d.%d", 
             P2P_VERSION_MAJOR, P2P_VERSION_MINOR, P2P_VERSION_PATCH);
    LOG_INFO("========================================");
    
    // Register signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize client
    if (client_init(&g_client, relay_host, relay_port) != 0) {
        LOG_FATAL("Failed to initialize client");
        return 1;
    }
    
    // Set callback
    client_set_message_callback(&g_client, on_message_received, NULL);
    
    // Connect
    if (client_connect(&g_client) != 0) {
        LOG_FATAL("Failed to connect to relay");
        client_cleanup(&g_client);
        return 1;
    }
    
    // Interactive loop
    print_commands();
    
    while (g_running && client_is_connected(&g_client)) {
        // Check for user input with timeout
        fd_set stdin_fds;
        FD_ZERO(&stdin_fds);
        FD_SET(STDIN_FILENO, &stdin_fds);
        
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int activity = select(STDIN_FILENO + 1, &stdin_fds, NULL, NULL, &timeout);
        
        if (activity > 0 && FD_ISSET(STDIN_FILENO, &stdin_fds)) {
            char cmd[64];
            if (fgets(cmd, sizeof(cmd), stdin)) {
                switch (cmd[0]) {
                    case 's':
                    case 'S':
                        print_status(&g_client);
                        break;
                        
                    case 'p':
                    case 'P':
                        client_send_ping(&g_client);
                        printf("> ");
                        fflush(stdout);
                        break;
                        
                    case 'q':
                    case 'Q':
                        g_running = 0;
                        break;
                        
                    case '\n':
                        printf("> ");
                        fflush(stdout);
                        break;
                        
                    default:
                        printf("Unknown command. ");
                        print_commands();
                        break;
                }
            }
        }
    }
    
    // Cleanup
    client_disconnect(&g_client);
    client_cleanup(&g_client);
    log_shutdown();
    
    printf("Client stopped.\n");
    return 0;
}