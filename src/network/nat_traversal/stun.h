#ifndef P2P_STUN_H
#define P2P_STUN_H

#include <stdint.h>
#include <stdbool.h>

// ============================================
// STUN PROTOCOL (RFC 5389)
// ============================================

#define STUN_MAGIC_COOKIE      0x2112A442
#define STUN_HEADER_SIZE       20
#define STUN_TRANSACTION_ID_SIZE 12

// Message types
#define STUN_BINDING_REQUEST   0x0001
#define STUN_BINDING_RESPONSE  0x0101
#define STUN_BINDING_ERROR     0x0111

// Attribute types
#define STUN_ATTR_MAPPED_ADDR      0x0001
#define STUN_ATTR_XOR_MAPPED_ADDR  0x0020
#define STUN_ATTR_SOFTWARE         0x8022
#define STUN_ATTR_FINGERPRINT      0x8028

// ============================================
// STUN HEADER
// ============================================
typedef struct __attribute__((packed)) {
    uint16_t type;
    uint16_t length;           // Payload length (not including header)
    uint32_t magic_cookie;
    uint8_t  transaction_id[STUN_TRANSACTION_ID_SIZE];
} stun_header_t;

// ============================================
// STUN RESULT
// ============================================
typedef struct {
    char public_ip[46];
    uint16_t public_port;
    bool success;
    double rtt_ms;             // Round-trip time
} stun_result_t;

// ============================================
// PUBLIC STUN SERVERS
// ============================================
typedef struct {
    const char* host;
    uint16_t port;
} stun_server_t;

// Well-known public STUN servers
static const stun_server_t STUN_SERVERS[] = {
    { "stun.l.google.com",    19302 },
    { "stun1.l.google.com",   19302 },
    { "stun2.l.google.com",   19302 },
    { "stun.stunprotocol.org", 3478 },
    { "stun.ekiga.net",        3478 },
};
#define STUN_SERVER_COUNT (sizeof(STUN_SERVERS) / sizeof(STUN_SERVERS[0]))

// ============================================
// API
// ============================================

// Send STUN binding request and get public IP/port
// udp_fd: existing UDP socket (or -1 to create one)
// Returns 0 on success
int stun_discover(int udp_fd, const char* stun_host, uint16_t stun_port,
                  stun_result_t* result, int timeout_ms);

// Try multiple STUN servers until one succeeds
int stun_discover_multi(int udp_fd, stun_result_t* result, int timeout_ms);

// Determine NAT type by comparing results from multiple STUN servers
// Requires sending from same local port to different servers
int stun_detect_nat_type(uint16_t local_port, int* nat_type_out);

#endif // P2P_STUN_H