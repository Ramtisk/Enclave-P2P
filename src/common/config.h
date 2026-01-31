#ifndef P2P_CONFIG_H
#define P2P_CONFIG_H

// ============================================
// VERSION
// ============================================
#define P2P_VERSION_MAJOR 0
#define P2P_VERSION_MINOR 1
#define P2P_VERSION_PATCH 0

// ============================================
// NETWORK CONFIGURATION
// ============================================
#define RELAY_HOST "127.0.0.1"
#define RELAY_PORT 5000
#define CLIENT_PORT_BASE 6000

// ============================================
// LIMITS
// ============================================
#define MAX_CLIENTS 64
#define MAX_ID_LENGTH 64
#define MAX_PAYLOAD_SIZE 4096
#define READ_BUFFER_SIZE 8192

// ============================================
// TIMEOUTS (milliseconds)
// ============================================
#define CONNECTION_TIMEOUT_MS 30000
#define PING_INTERVAL_MS 5000
#define RECONNECT_DELAY_MS 3000

// ============================================
// FEATURES (enable/disable)
// ============================================
#define ENABLE_DEBUG_LOGGING 1
#define ENABLE_ENCRYPTION 0  // Phase 2

#endif // P2P_CONFIG_H