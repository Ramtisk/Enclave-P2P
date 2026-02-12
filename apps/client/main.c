#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

#include "../../src/common/config.h"
#include "../../src/common/logging.h"
#include "../../src/network/client.h"
#include "../../src/transfer/chunking.h"
#include "../../src/transfer/p2p_transfer.h"

static p2p_client_t g_client;
static volatile int g_running = 1;

void signal_handler(int sig)
{
    (void)sig;
    printf("\n");
    LOG_INFO("Signal received, shutting down...");
    g_running = 0;
}

void on_message_received(message_t *msg, void *user_data)
{
    (void)user_data;

    switch (msg->header.type)
    {
    case MSG_ACK:
        // Check if it's a group creation ACK
        if (msg->header.payload_length >= sizeof(payload_group_created_t))
        {
            payload_group_created_t *created = (payload_group_created_t *)msg->payload;
            if (strlen(created->group_id) > 0)
            {
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
        }
        else
        {
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

void print_usage(const char *prog)
{
    printf("P2P Client v%d.%d.%d\n\n",
           P2P_VERSION_MAJOR, P2P_VERSION_MINOR, P2P_VERSION_PATCH);
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -r HOST   Relay host (default: %s)\n", RELAY_HOST);
    printf("  -p PORT   Relay port (default: %d)\n", RELAY_PORT);
    printf("  -v        Verbose mode (debug logging)\n");
    printf("  -h        Show this help\n");
}

void print_commands(void)
{
    printf("\n");
    printf("╔════════════════════════════════════════╗\n");
    printf("║           AVAILABLE COMMANDS           ║\n");
    printf("╠════════════════════════════════════════╣\n");
    printf("║  s          - Show status              ║\n");
    printf("║  p          - Send ping                ║\n");
    printf("╠════════════════════════════════════════╣\n");
    printf("║  c <name>   - Create group             ║\n");
    printf("║  j <token>  - Join group with token    ║\n");
    printf("║  l          - Leave current group      ║\n");
    printf("║  i          - Get new invite token     ║\n");
    printf("║  y          - Vote YES (approve join)  ║\n");
    printf("║  n          - Vote NO (reject join)    ║\n");
    printf("╠════════════════════════════════════════╣\n");
    printf("║  f <path>   - Share file               ║\n");
    printf("║  ls         - List shared files        ║\n");
    printf("║  r          - Refresh file list        ║\n");
    printf("║  d <hash>   - Download file by hash    ║\n");
    printf("╠════════════════════════════════════════╣\n");
    printf("║  nat        - Show NAT status          ║\n");
    printf("╠════════════════════════════════════════╣\n");
    printf("║  q          - Quit                     ║\n");
    printf("╚════════════════════════════════════════╝\n");
    printf("\n> ");
    fflush(stdout);
}

void print_status(p2p_client_t *client)
{
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
    if (client->in_group)
    {
        printf("║  Group ID:     %-24s ║\n", client->group_id);
        printf("║  Group Name:   %-24s ║\n", client->group_name);
    }
    if (client->has_pending_vote)
    {
        printf("╠════════════════════════════════════════╣\n");
        printf("║  *** PENDING VOTE REQUEST ***          ║\n");
        printf("║  From: %-32s ║\n", client->pending_vote_requester);
    }
    printf("╠════════════════════════════════════════╣\n");
    printf("║  P2P Port:    %-25d ║\n", client->p2p_listen_port);
    printf("║  Shared Files: %-24d ║\n", client->file_mgr.file_count);
    printf("╠════════════════════════════════════════╣\n");
    printf("║  Msgs sent:    %-24lu ║\n", client->messages_sent);
    printf("║  Msgs recv:    %-24lu ║\n", client->messages_received);
    printf("╚════════════════════════════════════════╝\n");
    printf("\n> ");
    fflush(stdout);
}

void print_shared_files(p2p_client_t *client)
{
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                           SHARED FILES                                   ║\n");
    printf("╠══════════════════════════════════════════════════════════════════════════╣\n");

    if (client->file_mgr.file_count == 0)
    {
        printf("║  No files shared yet. Use 'f <path>' to share a file.                    ║\n");
    }
    else
    {
        for (int i = 0; i < client->file_mgr.file_count; i++)
        {
            shared_file_t *file = &client->file_mgr.files[i];
            char hash_hex[65];
            hash_to_hex(file->metadata.file_hash, hash_hex, sizeof(hash_hex));

            printf("║  [%d] %-30s                                   ║\n", i + 1, file->metadata.filename);
            printf("║      Size: %-10lu bytes  Chunks: %-6u                           ║\n",
                   file->metadata.file_size, file->metadata.chunk_count);
            printf("║      Hash: %.64s ║\n", hash_hex);
            printf("║      Owner: %-20s  Available: %-3s                       ║\n",
                   file->owner_id, file->available ? "Yes" : "No");
            if (i < client->file_mgr.file_count - 1)
            {
                printf("╠──────────────────────────────────────────────────────────────────────────╣\n");
            }
        }
    }
    printf("╚══════════════════════════════════════════════════════════════════════════╝\n");
    printf("\n> ");
    fflush(stdout);
}

void handle_share_file(p2p_client_t *client, const char *filepath)
{
    if (access(filepath, R_OK) != 0)
    {
        printf("Error: Cannot access file '%s'\n", filepath);
        return;
    }
    
    printf("Sharing file: %s\n", filepath);
    
    int result = file_manager_share_file(&client->file_mgr, filepath, client->id);
    
    if (result == 0)
    {
        // Get the file we just added
        shared_file_t *file = &client->file_mgr.files[client->file_mgr.file_count - 1];
        char hash_hex[65];
        hash_to_hex(file->metadata.file_hash, hash_hex, sizeof(hash_hex));
        
        // Set our P2P port info
        strncpy(file->owner_ip, "127.0.0.1", sizeof(file->owner_ip) - 1);
        file->owner_port = client->p2p_listen_port;
        
        printf("\n");
        printf("╔════════════════════════════════════════════════════════════════════╗\n");
        printf("║                    FILE SHARED SUCCESSFULLY!                       ║\n");
        printf("╠════════════════════════════════════════════════════════════════════╣\n");
        printf("║  Filename: %-56.56s ║\n", file->metadata.filename);
        printf("║  Size:     %-10lu bytes                                        ║\n", file->metadata.file_size);
        printf("║  Chunks:   %-6u                                                  ║\n", file->metadata.chunk_count);
        printf("║  Hash:     %.60s... ║\n", hash_hex);
        printf("║  P2P Port: %-6d                                                  ║\n", file->owner_port);
        printf("╚════════════════════════════════════════════════════════════════════╝\n");
        
        // Announce to group if in one
        if (client->in_group)
        {
            printf("Announcing file to group...\n");
            client_announce_file(client, file);
        }
        else
        {
            printf("\nNote: Join a group to share this file with others.\n");
        }
        
        printf("\nOther peers can download using: d %s\n", hash_hex);
    }
    else if (result == -2)
    {
        printf("File already shared.\n");
    }
    else
    {
        printf("Failed to share file.\n");
    }
}

void handle_download_file(p2p_client_t *client, const char *hash_str)
{
    // ...existing code... (hash parsing and file lookup stays the same)

    // Convert hex string to binary hash
    uint8_t file_hash[FILE_HASH_SIZE];

    if (strlen(hash_str) < FILE_HASH_SIZE * 2)
    {
        printf("Error: Invalid hash (too short). Need %d hex characters.\n", FILE_HASH_SIZE * 2);
        return;
    }

    for (int i = 0; i < FILE_HASH_SIZE; i++)
    {
        unsigned int byte;
        if (sscanf(hash_str + i * 2, "%2x", &byte) != 1)
        {
            printf("Error: Invalid hash format.\n");
            return;
        }
        file_hash[i] = (uint8_t)byte;
    }

    shared_file_t *file = file_manager_find_by_hash(&client->file_mgr, file_hash);

    if (!file)
    {
        printf("Error: File not found. Use 'ls' to see available files.\n");
        return;
    }

    if (file->metadata.is_complete)
    {
        printf("You already have this file: %s\n", file->metadata.file_path);
        return;
    }

    char save_path[1024];
    int written = snprintf(save_path, sizeof(save_path), "%s/%s",
                           client->file_mgr.download_dir, file->metadata.filename);

    if (written < 0 || (size_t)written >= sizeof(save_path))
    {
        printf("Error: Path too long.\n");
        return;
    }

    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║                    STARTING DOWNLOAD                               ║\n");
    printf("╠════════════════════════════════════════════════════════════════════╣\n");
    printf("║  File:     %-56.56s ║\n", file->metadata.filename);
    printf("║  Size:     %-10lu bytes                                        ║\n", file->metadata.file_size);
    printf("║  Owner:    %-56.56s ║\n", file->owner_id);
    printf("║  Save to:  %-56.56s ║\n", save_path);
    printf("╚════════════════════════════════════════════════════════════════════╝\n");

    // NAT-aware connection: try direct → hole punch → relay fallback
    printf("\nEstablishing connection to peer...\n");
    
    int peer_fd = client_connect_to_peer(client, file->owner_id,
                                          file->owner_ip, file->owner_port);
    
    if (peer_fd >= 0)
    {
        printf("✅ Connected to peer (fd=%d)\n", peer_fd);
        printf("Downloading...\n");
        
        // Use the already-connected socket for transfer
        int result = p2p_download_file_with_fd(peer_fd, file_hash, save_path,
                                                NULL, NULL, NULL);
        
        if (result == 0)
        {
            printf("\n✅ Download complete: %s\n", save_path);
        }
        else
        {
            printf("\n❌ Download failed!\n");
        }
    }
    else
    {
        // Fallback: try original direct method (LAN)
        printf("⚠️  NAT punch failed, trying direct connection...\n");
        int result = p2p_download_file(file->owner_ip, file->owner_port,
                                       file_hash, save_path,
                                       NULL, NULL, NULL);
        if (result == 0)
        {
            printf("\n✅ Download complete: %s\n", save_path);
        }
        else
        {
            printf("\n❌ Download failed! Peer may be behind symmetric NAT.\n");
        }
    }
}

int main(int argc, char *argv[])
{
    const char *relay_host = RELAY_HOST;
    uint16_t relay_port = RELAY_PORT;
    log_level_t log_level = LOG_INFO;

    // Parse arguments
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-r") == 0 && i + 1 < argc)
        {
            relay_host = argv[++i];
        }
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
        {
            relay_port = (uint16_t)atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-v") == 0)
        {
            log_level = LOG_DEBUG;
        }
        else if (strcmp(argv[i], "-h") == 0)
        {
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
    if (client_init(&g_client, relay_host, relay_port) != 0)
    {
        LOG_FATAL("Failed to initialize client");
        return 1;
    }

    // Initialize file manager
    file_manager_init(&g_client.file_mgr, DEFAULT_SHARED_DIR, DEFAULT_DOWNLOAD_DIR);

    // Initialize P2P server for incoming transfers
    g_client.p2p_listen_port = P2P_LISTEN_PORT_BASE + (getpid() % 1000);
    if (p2p_server_init(&g_client.p2p_server, g_client.p2p_listen_port) == 0)
    {
        p2p_server_start(&g_client.p2p_server, &g_client.file_mgr);
        LOG_INFO("P2P server listening on port %d", g_client.p2p_listen_port);
    }
    else
    {
        LOG_WARN("Failed to start P2P server - incoming transfers won't work");
    }

    // Set callback
    client_set_message_callback(&g_client, on_message_received, NULL);

    // Connect
    if (client_connect(&g_client) != 0)
    {
        LOG_FATAL("Failed to connect to relay");
        client_cleanup(&g_client);
        return 1;
    }

    // Interactive loop
    print_commands();

    while (g_running && client_is_connected(&g_client))
    {
        fd_set stdin_fds;
        FD_ZERO(&stdin_fds);
        FD_SET(STDIN_FILENO, &stdin_fds);

        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int activity = select(STDIN_FILENO + 1, &stdin_fds, NULL, NULL, &timeout);

        if (activity > 0 && FD_ISSET(STDIN_FILENO, &stdin_fds))
        {
            char cmd[256];
            if (fgets(cmd, sizeof(cmd), stdin))
            {
                // Remove newline
                cmd[strcspn(cmd, "\n")] = 0;

                // Handle 'ls' command specially (two characters)
                if (strncmp(cmd, "ls", 2) == 0)
                {
                    print_shared_files(&g_client);
                    continue;
                }

                if (strncmp(cmd, "nat", 3) == 0)
                {
                    printf("\n");
                    printf("╔════════════════════════════════════════╗\n");
                    printf("║           NAT STATUS                   ║\n");
                    printf("╠════════════════════════════════════════╣\n");
                    printf("║  Local IP:    %-24s ║\n", g_client.nat_mgr.local_nat.local_ip);
                    printf("║  Local Port:  %-24d ║\n", g_client.nat_mgr.local_nat.local_port);
                    printf("║  Public IP:   %-24s ║\n", 
                           g_client.nat_mgr.local_nat.discovered ? 
                           g_client.nat_mgr.local_nat.public_ip : "(not discovered)");
                    printf("║  Public Port: %-24d ║\n", g_client.nat_mgr.local_nat.public_port);
                    printf("║  NAT Type:    %-24s ║\n", 
                           nat_type_string(g_client.nat_mgr.local_nat.nat_type));
                    printf("║  Discovered:  %-24s ║\n", 
                           g_client.nat_mgr.local_nat.discovered ? "Yes" : "No");
                    printf("╠════════════════════════════════════════╣\n");
                    printf("║  Active Punches: %-21d ║\n", g_client.nat_mgr.punch_count);
                    for (int i = 0; i < g_client.nat_mgr.punch_count; i++) {
                        printf("║  → %-12s  %-22s ║\n", 
                               g_client.nat_mgr.punches[i].peer_id,
                               punch_state_string(g_client.nat_mgr.punches[i].state));
                    }
                    printf("╚════════════════════════════════════════╝\n");
                    printf("\n> ");
                    fflush(stdout);
                    continue;
                }

                switch (cmd[0])
                {
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
                case 'C':
                {
                    // Create group: c <name>
                    char *name = cmd + 1;
                    while (*name == ' ')
                        name++;
                    if (strlen(name) > 0)
                    {
                        client_create_group(&g_client, name);
                    }
                    else
                    {
                        printf("Usage: c <group_name>\n");
                    }
                    printf("> ");
                    fflush(stdout);
                    break;
                }

                case 'j':
                case 'J':
                {
                    // Join group: j <token>
                    char *token = cmd + 1;
                    while (*token == ' ')
                        token++;
                    if (strlen(token) > 0)
                    {
                        client_join_group(&g_client, token);
                        printf("Join request sent. Waiting for approval...\n");
                    }
                    else
                    {
                        printf("Usage: j <invite_token>\n");
                    }
                    printf("> ");
                    fflush(stdout);
                    break;
                }

                case 'l':
                case 'L':
                    // Check if it's 'ls' that wasn't caught above
                    if (cmd[1] == 's' || cmd[1] == 'S')
                    {
                        print_shared_files(&g_client);
                    }
                    else
                    {
                        client_leave_group(&g_client);
                        printf("> ");
                        fflush(stdout);
                    }
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
                    if (g_client.has_pending_vote)
                    {
                        client_vote(&g_client, false);
                    }
                    else
                    {
                        printf("No pending vote.\n");
                    }
                    printf("> ");
                    fflush(stdout);
                    break;

                case 'f':
                case 'F':
                {
                    // Share file: f <path>
                    char *path = cmd + 1;
                    while (*path == ' ')
                        path++;
                    if (strlen(path) > 0)
                    {
                        handle_share_file(&g_client, path);
                    }
                    else
                    {
                        printf("Usage: f <filepath>\n");
                    }
                    printf("> ");
                    fflush(stdout);
                    break;
                }

                case 'd':
                case 'D':
                {
                    // Download file: d <hash>
                    char *hash = cmd + 1;
                    while (*hash == ' ')
                        hash++;
                    if (strlen(hash) > 0)
                    {
                        handle_download_file(&g_client, hash);
                    }
                    else
                    {
                        printf("Usage: d <file_hash>\n");
                    }
                    printf("> ");
                    fflush(stdout);
                    break;
                }

                case 'q':
                case 'Q':
                    g_running = 0;
                    break;

                case 'r':
                case 'R':
                    if (client_request_file_list(&g_client) == 0)
                    {
                        printf("File list requested...\n");
                    }
                    else
                    {
                        printf("Failed to request file list (are you in a group?)\n");
                    }
                    printf("> ");
                    fflush(stdout);
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
    p2p_server_stop(&g_client.p2p_server);
    p2p_server_cleanup(&g_client.p2p_server);
    file_manager_cleanup(&g_client.file_mgr);
    client_disconnect(&g_client);
    client_cleanup(&g_client);
    log_shutdown();

    printf("Client stopped.\n");
    return 0;
}