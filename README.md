# 🛡️ ENCLAVE P2P

> **⚠️ Status: Refactoring & Testing Phase** — The core architecture is implemented. The project is currently undergoing refactoring, bug fixing, and test coverage expansion before the final TUI and Docker packaging phases.

**ENCLAVE** is a high-security Peer-to-Peer (P2P) file-sharing system focused on **absolute privacy, user anonymity, and consensus-based access control.**

Unlike traditional P2P systems, ENCLAVE organizes itself into isolated "micro-networks" (Enclaves), where new members require unanimous approval to join, and identities cannot be correlated across groups.

---

## ✨ Key Features

- **Multi-Level Anonymity:** Unique IDs are generated per group. Being "User A" in Group 1 leaves no trace that you are the same person in Group 2.
- **Consensus-Based Membership:** New members can only join if **all** current members vote positively.
- **Resilience via Erasure Coding:** Files are split into shards using Reed-Solomon coding. Even if multiple members leave, the file can still be reconstructed from the remaining parts.
- **Ephemeral Groups:** The "Enclave" and its metadata self-destruct when the last member leaves.
- **Kademlia DHT:** Decentralized peer discovery reduces relay dependency.
- **NAT Traversal:** UDP hole punching with STUN/TURN fallback for connectivity behind NATs.
- **Post-Quantum Security (PQC):** Future-proof with quantum-resistant handshakes (Kyber).

---

## 🏗️ System Architecture

The project is divided into two main components written in **C (C11)**:

1. **Relay Server (The Sentinel):** Coordinates peer discovery, voting, and NAT traversal without ever touching the actual files or knowing real identities.
2. **Enclave Client (The Peer):** Manages encryption, file chunking, erasure coding, DHT routing, and direct P2P communication.

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

### Module Structure

```
src/
├── common/          # Config, logging, error handling
├── core/            # Group management, voting, identity
├── crypto/          # Ed25519 signatures, ChaCha20, key exchange, hashing
├── dht/             # Kademlia DHT (routing table, storage, protocol)
├── erasure/          # Reed-Solomon erasure coding (Galois GF(2⁸), shard distribution)
├── network/         # TCP/UDP transport, relay protocol, NAT traversal (STUN/TURN)
├── transfer/        # File chunking, Merkle trees, chunk transfer protocol
└── utils/           # Utility functions

apps/
├── client/          # Enclave Client entry point
└── relay/           # Relay Server entry point

tests/
├── unit/            # Unit tests
├── integration/     # Integration tests
└── scripts/         # Automated test scripts
```

---

## 🔒 Security Model

ENCLAVE uses a layered security stack:

| **Layer**         | **Technology**          | **Purpose**                                   |
|-------------------|-------------------------|-----------------------------------------------|
| Transport         | TLS 1.3 / TCP           | Protection against network sniffing           |
| Identity          | Ed25519                 | Digital signatures for proof of authorship    |
| Privacy           | ChaCha20-Poly1305       | Authenticated encryption for block transfers  |
| Future-Proofing   | Kyber (PQC)             | Quantum-resistant handshake                   |
| Integrity         | Merkle Trees (SHA-256)  | Ensures no block has been tampered with       |
| Redundancy        | Reed-Solomon GF(2⁸)     | File recovery even with significant peer loss |

---

## 🛠️ Technical Stack

| Component         | Technology                          |
|-------------------|-------------------------------------|
| Language          | C (C11)                             |
| Networking        | libuv (async event loop)            |
| Cryptography      | libsodium                           |
| Erasure Coding    | Custom Reed-Solomon over GF(2⁸)     |
| Peer Discovery    | Kademlia DHT (UDP)                  |
| NAT Traversal     | STUN / TURN / UDP Hole Punching     |
| Build System      | Makefile                            |

---

## 🚀 Quick Start

### Prerequisites

- GCC or Clang (C11 support)
- Make
- libsodium (`apt install libsodium-dev` / `brew install libsodium`)
- libuv (`apt install libuv1-dev` / `brew install libuv`)

### Build

```bash
git clone --recursive https://github.com/your-user/Enclave-P2P.git
cd Enclave-P2P
make all
```

### Run

```bash
# Terminal 1 — Start the relay server
./build/relay -v

# Terminal 2 — Start client A (creates a group)
./build/client -v

# Terminal 3 — Start client B (joins the group)
./build/client -v
```

### Docker (Coming Soon)

```bash
# Build the image
docker build -t enclave-p2p .

# Run relay
docker run -d --name relay -p 8080:8080 enclave-p2p relay

# Run client
docker run -it --name client enclave-p2p client
```

> Docker packaging is planned to simplify deployment and testing. A `docker-compose.yml` with a multi-peer test setup will be provided.

---

## 🧪 Testing

```bash
# Automated NAT traversal + transfer test
make test-nat-auto

# Full test suite
bash scripts/test_all.sh

# Manual multi-terminal test
make test-transfer
```

---

## 📅 Development Roadmap

- [x] **Phase 1:** Architecture & Protocol Definition
- [x] **Phase 2:** Core Relay Server & Basic Handshake
- [x] **Phase 3:** Group System & Consensus Voting
- [x] **Phase 4:** File Chunking & Direct P2P Transfer
- [x] **Phase 5:** NAT Traversal (STUN/TURN/Hole Punching)
- [x] **Phase 6:** Erasure Coding (Reed-Solomon GF(2⁸))
- [x] **Phase 7:** Kademlia DHT (Routing, Storage, Protocol)
- [ ] **Phase 8:** Refactoring, Bug Fixes & Test Coverage ← **In Progress**
- [ ] **Phase 9:** TUI — Terminal User Interface (ncurses)
- [ ] **Phase 10:** Docker Packaging & Deployment
- [ ] **Phase 11:** Security Audit & Hardening

---

## 📦 What's Implemented

| Module                  | Status | Description                                                |
|-------------------------|--------|------------------------------------------------------------|
| Relay Server            | [x]     | Peer coordination, group routing, NAT relay                |
| Client Core             | [x]     | Identity, group join/create, file commands                 |
| Crypto Layer            | [x]     | Ed25519, ChaCha20-Poly1305, key exchange, hashing          |
| Group System            | [x]     | Create/join/leave, unanimous voting, ephemeral groups      |
| File Chunking           | [x]     | SHA-256 Merkle trees, chunk transfer protocol              |
| NAT Traversal           | [x]     | STUN binding, UDP hole punching, TURN relay fallback       |
| Galois Field GF(2⁸)     | [x]     | Lookup tables, vector ops, matrix ops (Cauchy/Vandermonde) |
| Reed-Solomon Codec      | [x]     | Systematic encoding, reconstruction from any k-of-n shards|
| Shard Distribution      | [x]     | Peer assignment, health monitoring, local storage          |
| Kademlia Routing        | [x]     | 160-bit XOR distance, k-buckets, node lookup              |
| DHT Storage             | [x]     | Key-value store with TTL, pinning, republishing            |
| DHT Protocol            | [x]     | PING, FIND_NODE, FIND_VALUE, STORE over UDP               |
| TUI (ncurses)           | []     | Terminal interface for all operations                      |
| Docker                  | []     | Containerized deployment                                   |
| Security Audit          | []     | Formal review, fuzzing, hardening                          |

---

## 👥 Target Audience

ENCLAVE is designed for scenarios where trust is the most valuable asset:

- **Investigative Journalism:** Secure sharing of sources and documents.
- **Cybersecurity Teams:** Controlled exfiltration during Red Teaming.
- **Activists:** Communication in restrictive networks.
- **Research Groups:** Private collaboration on sensitive data.

---

## 📄 License

This project is under development. License TBD.

---

## ⚠️ Disclaimer

This software is under active development and is currently in the **refactoring and testing phase**. It should **not** be used for sharing critical or sensitive information until a security audit has been completed.