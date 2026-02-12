# 🛡️ ENCLAVE P2P 

> **Work In Progress (WIP):** This project is currently under active development. The architecture is defined, and the implementation of modules is being carried out according to the roadmap.

**ENCLAVE** is a high-security Peer-to-Peer (P2P) file-sharing system focused on **absolute privacy, user anonymity, and consensus-based access control.**. 

Unlike traditional P2P systems, ENCLAVE organizes itself into isolated "micro-networks" (Enclaves), where new members require unanimous approval to join, and identities cannot be correlated across groups.

---

## ✨ Key Features

*   **Multi-Level Anonymity:** Unique IDs are generated per group. Being "User A" in Group 1 leaves no trace that you are the same person in Group 2.

*   **Consensus-Based Membership:** New members can only join if **all** current members vote positively.

*   **Resilience via Erasure Coding:** Files are split into shards. Even if multiple members leave, the file can still be reconstructed from the remaining parts.

*   **Ephemeral Groups:** The "Enclave" and its metadata self-destruct when the last member leaves.

*   **Post-Quantum Security (PQC):** Future-proof with quantum-resistant handshakes.

---

## 🏗️ System Architecture

The project is divided into two main components written in **C**:

1.  **Relay Server (The Sentinel):** Coordinates peer discovery and voting without ever touching the actual files or knowing real identities.
2.  **Enclave Client (The Peer):** Manages encryption, file chunking, and direct P2P communication.

### Network flux Diagram

                      ┌──────────────────┐
                      │   RELAY SERVER   │
                      │  (Coordination)  │
                      └────────┬─────────┘
                               │
         ┌─────────────────────┼─────────────────────┐
         │                     │                     │
    ┌────▼──────┐        ┌─────▼─────┐         ┌─────▼─────┐
    │ ENCLAVE A │        │ ENCLAVE B │         │ ENCLAVE C │
    │ [P1] [P2] │        │ [P3] [P4] │         │ [P5] [P6] │
    └───────────┘        └───────────┘         └───────────┘
        ▲                     X                     X
        │ P2P Direct (TLS)    └─ No comunication────┘
        ▼                        between groups.
    ┌───────────┐
    │ 📁 Shards │
    └───────────┘

---

## 🔒 Security Model (Deep Dive)

ENCLAVE uses a layered security stack:

| **Camada**       | **Tecnologia**          | **Objetivo**                                  |
|------------------|-------------------------|-----------------------------------------------|
| Transport        | TLS 1.3 / TCP	         | Protection against network sniffing.          |
| Identity         | Ed25519                 | Digital signatures for proof of authorship.   |
| Privacy          | ChaCha20-Poly1305       | Authenticated encryption for block transfers. |
| Future-Proofing  | Kyber (PQC)             | Quantum-resistant handshake.                  |
| Integrity        | Merkle Trees (SHA-256)  | Ensures no block has been tampered with.      |

---

## 🛠️ Technical Stack

- **Language**: C (C11)
- **Networking:** libuv (Asynchronous event loop)
- **Cryptography:** libsodium
- **Error Correction:** libjerasure (Erasure Coding)
- **Build System:** Makefile / CMake

---

## 📅 Roadmap de Desenvolvimento

- [x] **Define Architecture and Protocol**
- [x] **Phase 1:** Core Relay Server and Basic Handshake (In Progress)
- [x] **Phase 2:** Group System and Voting Logic
- [x] **Phase 3:** File Chunking and Direct P2P Transfer
- [ ] **Phase 4:** Implement Erasure Coding and NAT Traversal
- [ ] **Phase 5:** CLI Interface (Ncurses) and Security Audit

---

## 👥 Target Audience

ENCLAVE is designed for scenarios where trust is the most valuable asset:

- **Investigative Journalism**: Secure sharing of sources.
- **Cybersecurity Teams**: Controlled exfiltration during Red Teaming.
- **Activists**: Communication in restrictive networks.

---

## ⚠️ Disclaimer

This software is under development. It should not be used for sharing critical information, for now.