#include "stun.h"
#include "../../common/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

// ============================================
// HELPERS
// ============================================

static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void generate_transaction_id(uint8_t tid[STUN_TRANSACTION_ID_SIZE]) {
    FILE* f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t n = fread(tid, 1, STUN_TRANSACTION_ID_SIZE, f);
        fclose(f);
        if (n == STUN_TRANSACTION_ID_SIZE) return;
    }
    // Fallback
    for (int i = 0; i < STUN_TRANSACTION_ID_SIZE; i++) {
        tid[i] = (uint8_t)(rand() & 0xFF);
    }
}

// ============================================
// STUN BINDING REQUEST
// ============================================

static int build_binding_request(uint8_t* buf, size_t buf_size,
                                  uint8_t tid[STUN_TRANSACTION_ID_SIZE]) {
    if (buf_size < STUN_HEADER_SIZE) return -1;
    
    stun_header_t* hdr = (stun_header_t*)buf;
    hdr->type = htons(STUN_BINDING_REQUEST);
    hdr->length = htons(0);  // No attributes
    hdr->magic_cookie = htonl(STUN_MAGIC_COOKIE);
    
    generate_transaction_id(tid);
    memcpy(hdr->transaction_id, tid, STUN_TRANSACTION_ID_SIZE);
    
    return STUN_HEADER_SIZE;
}

// ============================================
// PARSE STUN RESPONSE
// ============================================

static int parse_binding_response(const uint8_t* buf, size_t len,
                                   const uint8_t tid[STUN_TRANSACTION_ID_SIZE],
                                   stun_result_t* result) {
    if (len < STUN_HEADER_SIZE) {
        LOG_WARN("STUN: Response too short (%zu bytes)", len);
        return -1;
    }
    
    const stun_header_t* hdr = (const stun_header_t*)buf;
    
    // Verify it's a binding response
    uint16_t type = ntohs(hdr->type);
    if (type != STUN_BINDING_RESPONSE) {
        LOG_WARN("STUN: Unexpected response type: 0x%04x", type);
        return -1;
    }
    
    // Verify magic cookie
    if (ntohl(hdr->magic_cookie) != STUN_MAGIC_COOKIE) {
        LOG_WARN("STUN: Invalid magic cookie");
        return -1;
    }
    
    // Verify transaction ID
    if (memcmp(hdr->transaction_id, tid, STUN_TRANSACTION_ID_SIZE) != 0) {
        LOG_WARN("STUN: Transaction ID mismatch");
        return -1;
    }
    
    // Parse attributes
    uint16_t attr_len = ntohs(hdr->length);
    const uint8_t* ptr = buf + STUN_HEADER_SIZE;
    const uint8_t* end = ptr + attr_len;
    
    if ((size_t)(end - buf) > len) {
        LOG_WARN("STUN: Attributes exceed buffer");
        return -1;
    }
    
    while (ptr + 4 <= end) {
        uint16_t attr_type = ((uint16_t)ptr[0] << 8) | ptr[1];
        uint16_t attr_length = ((uint16_t)ptr[2] << 8) | ptr[3];
        ptr += 4;
        
        if (ptr + attr_length > end) break;
        
        if (attr_type == STUN_ATTR_XOR_MAPPED_ADDR && attr_length >= 8) {
            // XOR-MAPPED-ADDRESS
            uint8_t family = ptr[1];
            uint16_t xport = ((uint16_t)ptr[2] << 8) | ptr[3];
            
            result->public_port = xport ^ (uint16_t)(STUN_MAGIC_COOKIE >> 16);
            
            if (family == 0x01 && attr_length >= 8) {
                // IPv4
                uint32_t xaddr = ((uint32_t)ptr[4] << 24) | ((uint32_t)ptr[5] << 16) |
                                  ((uint32_t)ptr[6] << 8) | ptr[7];
                uint32_t addr = xaddr ^ STUN_MAGIC_COOKIE;
                
                struct in_addr in;
                in.s_addr = htonl(addr);
                inet_ntop(AF_INET, &in, result->public_ip, sizeof(result->public_ip));
                result->success = true;
                
                LOG_DEBUG("STUN: XOR-MAPPED-ADDRESS: %s:%u",
                          result->public_ip, result->public_port);
                return 0;
            }
        }
        else if (attr_type == STUN_ATTR_MAPPED_ADDR && attr_length >= 8) {
            // MAPPED-ADDRESS (non-XOR, older servers)
            uint8_t family = ptr[1];
            uint16_t port = ((uint16_t)ptr[2] << 8) | ptr[3];
            
            result->public_port = port;
            
            if (family == 0x01) {
                struct in_addr in;
                in.s_addr = htonl(((uint32_t)ptr[4] << 24) | ((uint32_t)ptr[5] << 16) |
                                   ((uint32_t)ptr[6] << 8) | ptr[7]);
                inet_ntop(AF_INET, &in, result->public_ip, sizeof(result->public_ip));
                result->success = true;
                
                LOG_DEBUG("STUN: MAPPED-ADDRESS: %s:%u",
                          result->public_ip, result->public_port);
                return 0;
            }
        }
        
        // Align to 4-byte boundary
        size_t padded = (attr_length + 3) & ~3u;
        ptr += padded;
    }
    
    LOG_WARN("STUN: No mapped address found in response");
    return -1;
}

// ============================================
// PUBLIC API
// ============================================

int stun_discover(int udp_fd, const char* stun_host, uint16_t stun_port,
                  stun_result_t* result, int timeout_ms) {
    bool created_socket = false;
    memset(result, 0, sizeof(stun_result_t));
    
    // Create UDP socket if not provided
    if (udp_fd < 0) {
        udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udp_fd < 0) {
            LOG_ERROR("STUN: socket(): %s", strerror(errno));
            return -1;
        }
        created_socket = true;
    }
    
    // Resolve STUN server
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", stun_port);
    
    int gai = getaddrinfo(stun_host, port_str, &hints, &res);
    if (gai != 0) {
        LOG_ERROR("STUN: getaddrinfo(%s): %s", stun_host, gai_strerror(gai));
        if (created_socket) close(udp_fd);
        return -1;
    }
    
    // Build and send request
    uint8_t request[STUN_HEADER_SIZE];
    uint8_t tid[STUN_TRANSACTION_ID_SIZE];
    int req_len = build_binding_request(request, sizeof(request), tid);
    
    uint64_t send_time = get_timestamp_ms();
    
    ssize_t sent = sendto(udp_fd, request, req_len, 0,
                           res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    
    if (sent != req_len) {
        LOG_ERROR("STUN: sendto failed: %s", strerror(errno));
        if (created_socket) close(udp_fd);
        return -1;
    }
    
    LOG_DEBUG("STUN: Binding request sent to %s:%u", stun_host, stun_port);
    
    // Wait for response
    struct pollfd pfd = { .fd = udp_fd, .events = POLLIN, .revents = 0 };
    int ready = poll(&pfd, 1, timeout_ms);
    
    if (ready <= 0) {
        LOG_WARN("STUN: %s from %s:%u", 
                 ready == 0 ? "Timeout" : "Poll error", stun_host, stun_port);
        if (created_socket) close(udp_fd);
        return -1;
    }
    
    // Receive response
    uint8_t response[1024];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    
    ssize_t received = recvfrom(udp_fd, response, sizeof(response), 0,
                                 (struct sockaddr*)&from_addr, &from_len);
    
    if (received <= 0) {
        LOG_ERROR("STUN: recvfrom failed: %s", strerror(errno));
        if (created_socket) close(udp_fd);
        return -1;
    }
    
    result->rtt_ms = (double)(get_timestamp_ms() - send_time);
    
    // Parse response
    int ret = parse_binding_response(response, (size_t)received, tid, result);
    
    if (created_socket) close(udp_fd);
    
    if (ret == 0) {
        LOG_INFO("STUN: Discovered public endpoint: %s:%u (RTT: %.1fms)",
                 result->public_ip, result->public_port, result->rtt_ms);
    }
    
    return ret;
}

int stun_discover_multi(int udp_fd, stun_result_t* result, int timeout_ms) {
    for (size_t i = 0; i < STUN_SERVER_COUNT; i++) {
        LOG_DEBUG("STUN: Trying server %s:%u...",
                  STUN_SERVERS[i].host, STUN_SERVERS[i].port);
        
        if (stun_discover(udp_fd, STUN_SERVERS[i].host, STUN_SERVERS[i].port,
                          result, timeout_ms) == 0) {
            return 0;
        }
    }
    
    LOG_WARN("STUN: All servers failed");
    return -1;
}

int stun_detect_nat_type(uint16_t local_port, int* nat_type_out) {
    // Create a UDP socket bound to local_port
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) return -1;
    
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(local_port);
    
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    
    // Test 1: Query first STUN server
    stun_result_t result1 = {0};
    if (stun_discover(fd, STUN_SERVERS[0].host, STUN_SERVERS[0].port,
                      &result1, 3000) != 0) {
        close(fd);
        *nat_type_out = 4; // Unknown/blocked
        return -1;
    }
    
    // Test 2: Query second STUN server from same socket
    stun_result_t result2 = {0};
    if (STUN_SERVER_COUNT > 1) {
        stun_discover(fd, STUN_SERVERS[1].host, STUN_SERVERS[1].port,
                      &result2, 3000);
    }
    
    close(fd);
    
    // Compare results
    if (!result2.success) {
        // Could only reach one server
        *nat_type_out = 2; // Restricted cone (guess)
        return 0;
    }
    
    if (result1.public_port == result2.public_port &&
        strcmp(result1.public_ip, result2.public_ip) == 0) {
        // Same mapped address from both servers
        if (result1.public_port == local_port) {
            *nat_type_out = 0; // No NAT / Full cone
        } else {
            *nat_type_out = 1; // Full cone NAT (port-preserving)
        }
    } else if (strcmp(result1.public_ip, result2.public_ip) == 0 &&
               result1.public_port != result2.public_port) {
        // Same IP but different ports — symmetric NAT
        *nat_type_out = 3; // Symmetric
    } else {
        // Different IPs — multi-homed or symmetric
        *nat_type_out = 3; // Symmetric
    }
    
    LOG_INFO("STUN: NAT type detected: %d (0=None, 1=FullCone, 2=Restricted, 3=Symmetric)",
             *nat_type_out);
    return 0;
}