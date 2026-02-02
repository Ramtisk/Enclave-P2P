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
            // Check if it's a group creation ACK
            if (msg->header.payload_length >= sizeof(payload_group_created_t)) {
                payload_group_created_t* created = (payload_group_created_t*)msg->payload;
                if (strlen(created->group_id) > 0) {
                    strncpy(g_client.group_id, created->group_id, MAX_ID_LENGTH - 1);
                    strncpy(g_client.invite_token, created->invite_token, 
                           INVITE_TOKEN_LENGTH - 1);
                    g_client.in_group = true;
                    
                    printf("\n");
                    printf("╔════════════════════════════════════════╗\n");
                    printf("║         GROUP CREATED!                 ║\n");
                    printf("╠════════════════════════════════════════╣\n");
                    printf("║ Group ID: %-28s ║\n", created->group_id);
                    printf("║ Invite Token: %-24s ║\n", created->invite_token);
                    printf("╚════════════════════════════════════════╝\n");
                    printf("\nShare this token with others to invite them!\n");
                }
            } else {
                LOG_INFO("Received ACK from relay");
            }
            break;
        case MSG_PONG:
            // Handled internally
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
    printf("\n");
    printf("╔════════════════════════════════════════╗\n");
    printf("║           AVAILABLE COMMANDS           ║\n");
    printf("╠════════════════════════════════════════╣\n");
    printf("║  s        - Show status                ║\n");
    printf("║  p        - Send ping                  ║\n");
    printf("║  c <name> - Create group               ║\n");
    printf("║  j <token>- Join group with token      ║\n");
    printf("║  l        - Leave current group        ║\n");
    printf("║  i        - Get new invite token       ║\n");
    printf("║  y        - Vote YES (approve join)    ║\n");
    printf("║  n        - Vote NO (reject join)      ║\n");
    printf("║  q        - Quit                       ║\n");
    printf("╚════════════════════════════════════════╝\n");
    printf("\n> ");
    fflush(stdout);
}

void print_status(p2p_client_t* client) {
    printf("\n");
    printf("╔════════════════════════════════════════╗\n");
    printf("║           CLIENT STATUS                ║\n");
    printf("╠════════════════════════════════════════╣\n");
    printf("║  ID:           %-24s ║\n", client->id);
    printf("║  Connected:    %-24s ║\n", client->connected ? "Yes" : "No");
    printf("║  Relay:        %s:%-17d ║\n", client->relay_host, client->relay_port);
    printf("║  RTT:          %-20lu ms ║\n", client->rtt_ms);
    printf("╠════════════════════════════════════════╣\n");
    printf("║  In Group:     %-24s ║\n", client->in_group ? "Yes" : "No");
    if (client->in_group) {
        printf("║  Group ID:     %-24s ║\n", client->group_id);
        printf("║  Group Name:   %-24s ║\n", client->group_name);
    }
    if (client->has_pending_vote) {
        printf("╠════════════════════════════════════════╣\n");
        printf("║  *** PENDING VOTE REQUEST ***          ║\n");
        printf("║  From: %-32s ║\n", client->pending_vote_requester);
    }
    printf("╠════════════════════════════════════════╣\n");
    printf("║  Msgs sent:    %-24lu ║\n", client->messages_sent);
    printf("║  Msgs recv:    %-24lu ║\n", client->messages_received);
    printf("╚════════════════════════════════════════╝\n");
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
        fd_set stdin_fds;
        FD_ZERO(&stdin_fds);
        FD_SET(STDIN_FILENO, &stdin_fds);
        
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int activity = select(STDIN_FILENO + 1, &stdin_fds, NULL, NULL, &timeout);
        
        if (activity > 0 && FD_ISSET(STDIN_FILENO, &stdin_fds)) {
            char cmd[128];
            if (fgets(cmd, sizeof(cmd), stdin)) {
                // Remove newline
                cmd[strcspn(cmd, "\n")] = 0;
                
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
                        
                    case 'c':
                    case 'C': {
                        // Create group: c <name>
                        char* name = cmd + 1;
                        while (*name == ' ') name++;
                        if (strlen(name) > 0) {
                            client_create_group(&g_client, name);
                        } else {
                            printf("Usage: c <group_name>\n");
                        }
                        printf("> ");
                        fflush(stdout);
                        break;
                    }
                    
                    case 'j':
                    case 'J': {
                        // Join group: j <token>
                        char* token = cmd + 1;
                        while (*token == ' ') token++;
                        if (strlen(token) > 0) {
                            client_join_group(&g_client, token);
                            printf("Join request sent. Waiting for approval...\n");
                        } else {
                            printf("Usage: j <invite_token>\n");
                        }
                        printf("> ");
                        fflush(stdout);
                        break;
                    }
                    
                    case 'l':
                    case 'L':
                        client_leave_group(&g_client);
                        printf("> ");
                        fflush(stdout);
                        break;
                        
                    case 'i':
                    case 'I':
                        client_request_invite(&g_client);
                        printf("> ");
                        fflush(stdout);
                        break;
                        
                    case 'y':
                    case 'Y':
                        client_vote(&g_client, true);
                        printf("> ");
                        fflush(stdout);
                        break;
                        
                    case 'n':
                    case 'N':
                        if (g_client.has_pending_vote) {
                            client_vote(&g_client, false);
                        } else {
                            printf("No pending vote.\n");
                        }
                        printf("> ");
                        fflush(stdout);
                        break;
                        
                    case 'q':
                    case 'Q':
                        g_running = 0;
                        break;
                        
                    case '\0':
                        printf("> ");
                        fflush(stdout);
                        break;
                        
                    case 'h':
                    case 'H':
                    case '?':
                        print_commands();
                        break;
                        
                    default:
                        printf("Unknown command. Press 'h' for help.\n");
                        printf("> ");
                        fflush(stdout);
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