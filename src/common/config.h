#ifndef P2P_CONFIG_H
#define P2P_CONFIG_H

// ============================================
// VERSION
// ============================================
#define P2P_VERSION_MAJOR 0
#define P2P_VERSION_MINOR 3
#define P2P_VERSION_PATCH 0

// ============================================
// NETWORK CONFIGURATION
// ============================================
#define RELAY_HOST "127.0.0.1"
#define RELAY_PORT 5000
#define CLIENT_PORT_BASE 6000
#define P2P_LISTEN_PORT_BASE 7000

// ============================================
// LIMITS
// ============================================
#define MAX_CLIENTS 64
#define MAX_ID_LENGTH 64
#define MAX_PAYLOAD_SIZE 8192
#define READ_BUFFER_SIZE 16384

// ============================================
// GROUP LIMITS (Phase 2)
// ============================================
#define MAX_GROUPS 32
#define MAX_GROUP_MEMBERS 16
#define MAX_PENDING_JOINS 8
#define VOTE_TIMEOUT_MS 60000

// ============================================
// FILE TRANSFER LIMITS (Phase 3)
// ============================================
#define MAX_SHARED_FILES 128
#define MAX_ACTIVE_TRANSFERS 8
#define CHUNK_SIZE 4096
#define MAX_FILENAME_LENGTH 256
#define TRANSFER_TIMEOUT_MS 30000
#define CHUNK_RETRY_COUNT 3

// ============================================
// TIMEOUTS (milliseconds)
// ============================================
#define CONNECTION_TIMEOUT_MS 30000
#define PING_INTERVAL_MS 5000
#define RECONNECT_DELAY_MS 3000

// ============================================
// PATHS
// ============================================
#define DEFAULT_SHARED_DIR "./data/shared"
#define DEFAULT_DOWNLOAD_DIR "./data/downloads"

// ============================================
// FEATURES (enable/disable)
// ============================================
#define ENABLE_DEBUG_LOGGING 1
#define ENABLE_ENCRYPTION 0

#endif // P2P_CONFIG_H