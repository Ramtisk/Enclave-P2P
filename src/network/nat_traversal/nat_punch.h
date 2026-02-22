#ifndef P2P_NAT_PUNCH_H
#define P2P_NAT_PUNCH_H

#include "nat_types.h"

/*  ============================================
    NAT HOLE PUNCH API

    Note: UDP hole punching + TCP punch-through strategies.
    ============================================ */

// Orchestrate punch to peer via relay (sends MSG_NAT_PUNCH_REQ).
int nat_punch_to_peer(nat_manager_t* mgr, int relay_socket_fd,
                      const char* peer_id, const char* sender_id);

// Handle incoming punch instruction from relay.
// Tries multiple strategies in order:
//   1. Direct TCP to LAN address
//   2. TCP to public endpoint
//   3. TCP to public IP + P2P port
//   4. UDP hole punch → TCP retry
//   5. Relay fallback
// Returns connected fd or -1.
int nat_handle_punch_instruction(nat_manager_t* mgr,
                                  const payload_punch_instruction_t* instr);

// UDP hole punch subroutine (sends probes, waits for response).
// Returns UDP fd on success, -1 on failure.
int nat_udp_hole_punch(nat_manager_t* mgr, punch_context_t* punch);

// TCP connect with timeout + optional local port binding.
int nat_try_connect(const char* ip, uint16_t port,
                    uint16_t local_port, int timeout_ms);

#endif // P2P_NAT_PUNCH_H