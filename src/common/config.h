#ifndef P2P_CONFIG_H
#define P2P_CONFIG_H

/*  ============================================
    VERSION

    Note: The version is split into MAJOR, MINOR, and PATCH
    to follow semantic versioning:
    - MAJOR: Incompatible API changes or major new features.
    - MINOR: Backwards-compatible feature additions or improvements.
    - PATCH: Backwards-compatible bug fixes or small changes.
    This allows users and developers to quickly understand the
    impact of updates and ensure compatibility.
    Its printed on the clients & relay menu.

    ============================================ */
#define P2P_VERSION_MAJOR 0
#define P2P_VERSION_MINOR 3
#define P2P_VERSION_PATCH 0

/*  ============================================
    NETWORK CONFIGURATION
    
    Note: Default relay and client * Network * configurations
    are set here.
    - On RELAY_HOST & RELAY_PORT the default values are, respectively, 127.0.0.1 and 5000.
    - On CLIENT_PORT_BASE, the base port for clients is set to 6000:
        Each client will use a port in the range [6000, 6999] based on its PID.
    - On P2P_LISTEN_PORT_BASE, the base port for P2P connections is set to 7000: 
        Each client will listen for P2P connections on a port in, and note that p2p connections happen on Downloads.

    ============================================ */
#define RELAY_HOST "127.0.0.1"
#define RELAY_PORT 5000
#define CLIENT_PORT_BASE 6000
#define P2P_LISTEN_PORT_BASE 7000

/*  ============================================
    LIMITS

    Note: Defines core limits for clients, IDs, and buffer sizes.
    - MAX_CLIENTS: Maximum number of clients supported by the relay.
    - MAX_ID_LENGTH: Maximum length for user/group IDs.
    - MAX_PAYLOAD_SIZE: Maximum size for a single message payload (bytes).
    - READ_BUFFER_SIZE: Buffer size for reading network data (bytes).

    ============================================ */
#define MAX_CLIENTS 64
#define MAX_ID_LENGTH 64
#define MAX_PAYLOAD_SIZE 8192
#define READ_BUFFER_SIZE 16384

/*  ============================================
    GROUP LIMITS (Phase 2)

    Note: Limits for group management and voting.
    - MAX_GROUPS: Maximum number of groups managed by the relay.
    - MAX_GROUP_MEMBERS: Maximum members allowed in a single group.
    - MAX_PENDING_JOINS: Maximum pending join requests per group.
    - VOTE_TIMEOUT_MS: Timeout for group join voting (milliseconds), set on 1 minute now.

    ============================================ */
#define MAX_GROUPS 32
#define MAX_GROUP_MEMBERS 16
#define MAX_PENDING_JOINS 8
#define VOTE_TIMEOUT_MS 60000

/*  ============================================
    FILE TRANSFER LIMITS (Phase 3)

    Note: Limits for file sharing and transfer operations.
    - MAX_SHARED_FILES: Maximum files a client can share.
    - MAX_ACTIVE_TRANSFERS: Maximum concurrent file transfers per client.
    - CHUNK_SIZE: Size of each file chunk (bytes).
    - MAX_FILENAME_LENGTH: Maximum length for filenames.
    - TRANSFER_TIMEOUT_MS: Timeout for a file transfer operation (milliseconds).
    - CHUNK_RETRY_COUNT: Number of retries for a failed chunk transfer.

    ============================================ */
#define MAX_SHARED_FILES 128
#define MAX_ACTIVE_TRANSFERS 8
#define CHUNK_SIZE 4096
#define MAX_FILENAME_LENGTH 256
#define TRANSFER_TIMEOUT_MS 30000
#define CHUNK_RETRY_COUNT 3

/*  ============================================
    TIMEOUTS (milliseconds)

    Note: General timeout settings for network operations.
    - CONNECTION_TIMEOUT_MS: Timeout for establishing network connections.
    - PING_INTERVAL_MS: Interval between PING messages to peers.
    - RECONNECT_DELAY_MS: Delay before attempting to reconnect after failure.

    ============================================ */
#define CONNECTION_TIMEOUT_MS 30000
#define PING_INTERVAL_MS 5000
#define RECONNECT_DELAY_MS 3000

/*  ============================================
    PATHS

    Note: Default directories for shared and downloaded files.
    - DEFAULT_SHARED_DIR: Directory for files available to share.
    - DEFAULT_DOWNLOAD_DIR: Directory for received/downloaded files.

    ============================================ */
#define DEFAULT_SHARED_DIR "./data/shared"
#define DEFAULT_DOWNLOAD_DIR "./data/downloads"
#define DEFAULT_LOG_DIR "./data/logs"

/*  ============================================
    FEATURES (enable/disable)

    Note: Feature toggles for debugging and encryption.
    - ENABLE_DEBUG_LOGGING: Set to 1 to enable debug logs.
    - ENABLE_ENCRYPTION: Set to 1 to enable encryption features.

    ============================================ */
#define ENABLE_DEBUG_LOGGING 1
#define ENABLE_ENCRYPTION 0

#endif